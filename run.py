"""PyInstaller entry point (a module isn't directly buildable)."""

from dohproxy.main import main

if __name__ == "__main__":
    raise SystemExit(main())
