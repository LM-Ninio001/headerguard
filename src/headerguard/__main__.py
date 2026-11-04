"""Entry point so the tool can be run with `python -m headerguard`."""

from headerguard import __version__


def main() -> None:
    print(f"HeaderGuard v{__version__}")
    print("Scanning is coming in the next stage. Stay tuned!")


if __name__ == "__main__":
    main()
