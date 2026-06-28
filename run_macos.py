"""PyInstaller entry point for the macOS build (a module isn't directly buildable)."""

from dohproxy.macos.main import main

if __name__ == "__main__":
    raise SystemExit(main())
