"""SSH source adapter — reads logs from a remote host over SSH.

For servers reachable only over SSH and without a log-aggregation stack,
this adapter pulls logs straight over an existing SSH connection — no agent
on the remote box, no open port, no daemon.

It shells out to the system `ssh` client (no Python SSH dependency), so
`~/.ssh/config` — jump hosts, per-host keys, the agent, known_hosts — all
work unchanged. SSH is only a transport: the remote data source is either a
log file (read with `tail`) or the systemd journal (`journalctl -o json`),
and the inner content is parsed exactly like a local file or journal.
"""

from __future__ import annotations

import asyncio
import json
import shlex
import subprocess
from collections.abc import AsyncIterator

from ..models import Event
from ..parsers.detector import FormatDetector
from ..parsers.registry import get_parser
from .base import SourceAdapter
from .journald import _map_entry


class SSHAdapter(SourceAdapter):
    """Reads log events from a remote host via the system `ssh` client.

    Two remote sources are supported:
      * a log file  — pass ``path`` (read with ``tail``)
      * the journal — pass ``use_journald`` or ``unit`` (``journalctl -o json``)
    """

    def __init__(
        self,
        *,
        host: str,
        path: str | None = None,
        unit: str | None = None,
        use_journald: bool = False,
        since: str | None = None,
        lines: int = 1000,
        port: int | None = None,
        identity: str | None = None,
        ssh_opts: list[str] | None = None,
        runner=None,
        stream_runner=None,
    ) -> None:
        self._host = host
        self._path = path
        self._unit = unit
        self._journald = use_journald or unit is not None
        self._since = since
        self._lines = lines
        self._port = port
        self._identity = identity
        self._ssh_opts = list(ssh_opts or [])
        self._runner = runner  # batch, injectable for tests: (list[str]) -> str
        self._stream_runner = stream_runner  # follow: (list[str]) -> AsyncIterator[str]

        if not self._journald and not self._path:
            raise ValueError("SSHAdapter needs either a remote 'path' or journald mode.")

        # host label for tagging events — drop any 'user@' prefix for readability
        self._host_label = host.split("@")[-1]

    # -- ssh / remote command construction ---------------------------------

    def _ssh_base(self, *, follow: bool) -> list[str]:
        args = ["ssh"]
        if self._port is not None:
            args += ["-p", str(self._port)]
        if self._identity:
            args += ["-i", self._identity]
        for opt in self._ssh_opts:  # user options first — ssh keeps the first value
            args += ["-o", opt]
        args += ["-o", "ConnectTimeout=10"]
        if follow:
            # detect a silently-dropped connection so ssh exits and we reconnect
            args += ["-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3"]
        return args

    def _remote_cmd(self, *, follow: bool, first: bool = True, cursor: str | None = None) -> str:
        """Build the command string run on the remote host."""
        if self._journald:
            parts = ["journalctl", "-o", "json", "--no-pager"]
            if self._unit:
                parts += ["-u", shlex.quote(self._unit)]
            if follow:
                parts.append("-f")
                if cursor:
                    parts += ["--after-cursor", shlex.quote(cursor)]
                else:
                    parts += ["-n", str(self._lines)]
            else:
                if self._since:
                    parts += ["--since", shlex.quote(self._since)]
                parts += ["-n", str(self._lines)]
            return " ".join(parts)

        # file mode
        qpath = shlex.quote(self._path or "")
        if follow:
            # the first connection backfills the last N lines; reconnects do
            # not, so already-seen lines are never re-emitted as duplicates
            backfill = self._lines if first else 0
            return f"tail -n {backfill} -F {qpath}"
        return f"tail -n {self._lines} {qpath}"

    def _batch_args(self) -> list[str]:
        return [*self._ssh_base(follow=False), self._host, self._remote_cmd(follow=False)]

    def _sample_args(self) -> list[str]:
        """A tiny batch read used once to detect a remote file's format."""
        qpath = shlex.quote(self._path or "")
        return [*self._ssh_base(follow=False), self._host, f"tail -n 5 {qpath}"]

    def _follow_args(self, *, first: bool, cursor: str | None) -> list[str]:
        return [
            *self._ssh_base(follow=True),
            self._host,
            self._remote_cmd(follow=True, first=first, cursor=cursor),
        ]

    # -- runners (real subprocess; overridable for tests) ------------------

    def _run_batch(self, args: list[str]) -> str:
        if self._runner is not None:
            return self._runner(args)
        try:
            result = subprocess.run(args, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            raise RuntimeError("ssh not found — install an OpenSSH client to use the ssh adapter.")
        if result.returncode != 0:
            detail = result.stderr.strip() or f"exit code {result.returncode}"
            raise RuntimeError(f"ssh failed: {detail}")
        return result.stdout

    async def _stream(self, args: list[str]) -> AsyncIterator[str]:
        """Yield stdout lines from a long-lived ssh process.

        Raises RuntimeError only when the process produced no output at all
        (a clear connection or auth failure). A non-zero exit *after* output
        is treated as a dropped connection — the caller reconnects.
        """
        if self._stream_runner is not None:
            async for line in self._stream_runner(args):
                yield line
            return
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            raise RuntimeError("ssh not found — install an OpenSSH client to use the ssh adapter.")
        try:
            assert proc.stdout is not None
            yielded = 0
            async for raw in proc.stdout:
                yielded += 1
                yield raw.decode("utf-8", errors="replace")
            await proc.wait()
            if proc.returncode and yielded == 0:
                err = ""
                if proc.stderr is not None:
                    data = await proc.stderr.read()
                    err = data.decode("utf-8", errors="replace").strip()
                raise RuntimeError(f"ssh failed: {err or f'exit code {proc.returncode}'}")
        finally:
            if proc.returncode is None:
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass

    # -- event mapping -----------------------------------------------------

    def _map_json_line(self, line: str) -> Event | None:
        """journald mode: map one `journalctl -o json` line to an Event."""
        line = line.strip()
        if not line:
            return None
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return None
        event = _map_entry(entry)
        if event is None:
            return None
        event.source = f"{self._host_label}:{event.source}"
        event.parsed_fields["ssh_host"] = self._host_label
        return event

    def _make_file_parser(self, sample: list[str]):
        fmt = FormatDetector().detect(sample)
        return get_parser(fmt, source=f"{self._host_label}:{self._path}")

    def _tag(self, event: Event) -> Event:
        event.parsed_fields["ssh_host"] = self._host_label
        return event

    # -- public API --------------------------------------------------------

    async def events(self) -> AsyncIterator[Event]:
        """Read remote logs once (batch mode)."""
        output = self._run_batch(self._batch_args())
        if self._journald:
            for line in output.splitlines():
                event = self._map_json_line(line)
                if event is not None:
                    yield event
        else:
            lines = output.splitlines(keepends=True)
            sample = [ln for ln in lines if ln.strip()][:5]
            parser = self._make_file_parser(sample)
            for line in lines:
                event = parser.parse(line)
                if event is not None:
                    yield self._tag(event)

    async def poll(self, interval: float) -> AsyncIterator[Event]:
        """Follow remote logs in real time over a long-lived ssh connection.

        The connection streams continuously (`journalctl -f` / `tail -F`).
        When it drops, the adapter reconnects after `interval` seconds. In
        journald mode it resumes from the last `__CURSOR` via `--after-cursor`,
        so no entry is missed and none repeats; in file mode a reconnect skips
        the backfill, so lines written during the outage may be missed (but
        never duplicated). Runs until the caller stops iterating.
        """
        cursor: str | None = None
        parser = None
        if not self._journald:
            # one quick batch read up front so the format is known before the
            # live stream starts — keeps the streaming loop free of buffering
            sample_out = self._run_batch(self._sample_args())
            sample = [ln for ln in sample_out.splitlines(keepends=True) if ln.strip()][:5]
            parser = self._make_file_parser(sample)

        first = True
        while True:
            try:
                async for line in self._stream(self._follow_args(first=first, cursor=cursor)):
                    if self._journald:
                        event = self._map_json_line(line)
                        if event is None:
                            continue
                        cur = event.parsed_fields.get("__cursor")
                        if cur:
                            cursor = str(cur)
                        yield event
                    else:
                        assert parser is not None
                        event = parser.parse(line)
                        if event is not None:
                            yield self._tag(event)
            except RuntimeError:
                if first:
                    raise  # the initial connection failed — surface the error
                # a later reconnect failed — keep retrying after the backoff
            first = False
            await asyncio.sleep(interval)
