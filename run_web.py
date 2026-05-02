"""
Phish X - Web launcher
Starts the FastAPI server and opens the app in the default browser.
Run with:  python run_web.py
"""

import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path

# Make sure the app package is importable from the project root
sys.path.insert(0, str(Path(__file__).resolve().parent))

_PORTS = [8000, 8001, 8080, 8888]


def _port_free(port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False


def _open_browser(url: str):
    """Wait briefly then open the URL so the server has time to start."""
    time.sleep(1.5)
    webbrowser.open(url)


def main():
    port = next((p for p in _PORTS if _port_free(p)), None)
    if port is None:
        print("ERROR: No free port found (tried %s). Close other instances." % _PORTS)
        sys.exit(1)

    url = "http://127.0.0.1:%d/static/" % port
    print("=" * 55)
    print("  Phish X - Security Awareness Training Platform")
    print("=" * 55)
    print("  Starting server on %s" % url)
    print("  Opening browser automatically…")
    print("  Press Ctrl+C to stop.")
    print("=" * 55)

    threading.Thread(target=_open_browser, args=(url,), daemon=True).start()

    import uvicorn
    from app.main import app
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
