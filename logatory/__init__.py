from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("logatory")
except PackageNotFoundError:  # running from source without install
    __version__ = "0.0.0+dev"
