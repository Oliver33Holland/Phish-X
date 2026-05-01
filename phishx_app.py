"""
Phish X – Full desktop application with embedded browser (Chromium).
No Internet Explorer or external browser: everything runs inside the app window.
"""

import socket
import sys
import threading
import time
from pathlib import Path

if getattr(sys, "frozen", False):
    sys.path.insert(0, str(Path(sys._MEIPASS)))
    # In windowed mode sys.stdout/stderr are None, which crashes uvicorn's logger.
    # Redirect both to a log file next to the exe.
    import io
    _log_path = Path(sys.executable).resolve().parent / "phishx_server.log"
    try:
        _log_fp = open(_log_path, "w", encoding="utf-8", buffering=1)
        sys.stdout = _log_fp
        sys.stderr = _log_fp
    except Exception:
        sys.stdout = io.StringIO()
        sys.stderr = io.StringIO()
else:
    # Project root contains the app/ package directly
    sys.path.insert(0, str(Path(__file__).resolve().parent))

_PORTS = [8000, 8001, 8080, 8888]

# In a windowed PyInstaller build sys.stdin/stdout are None – guard against that.
def _fatal(title: str, message: str) -> None:
    """Show an error dialog then exit. Works in both windowed and console mode."""
    try:
        from PyQt6.QtWidgets import QApplication, QMessageBox
        _app = QApplication.instance() or QApplication(sys.argv)
        box = QMessageBox()
        box.setWindowTitle(title)
        box.setText(message)
        box.setIcon(QMessageBox.Icon.Critical)
        box.exec()
    except Exception:
        # Absolute last resort – only works when a console is present
        try:
            sys.stderr.write(title + ": " + message + "\n")
        except Exception:
            pass
    sys.exit(1)


def _port_free(port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False


_server_error: str = ""


def _log_dir() -> Path:
    """Return a writable directory for logs – next to the exe when frozen."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def run_server(port: int):
    global _server_error
    try:
        import uvicorn
        from app.main import app
        uvicorn.run(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
            # Disable uvicorn's custom log formatter so it doesn't
            # call isatty() on sys.stderr (which is None in windowed builds)
            log_config=None,
        )
    except Exception as exc:
        import traceback
        _server_error = traceback.format_exc()
        # Write to log file so it survives the process
        try:
            log_path = _log_dir() / "phishx_error.log"
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(_server_error)
        except Exception:
            pass


def main():
    port = None
    for p in _PORTS:
        if _port_free(p):
            port = p
            break
    if port is None:
        _fatal(
            "Phish X – Port error",
            "No free port available (tried %s).\n\nClose other Phish X instances and try again." % _PORTS,
        )

    server_thread = threading.Thread(target=run_server, args=(port,), daemon=True)
    server_thread.start()

    # Give the server up to 60 seconds to start (first run may be slow)
    url = "http://127.0.0.1:%s/" % port
    for _ in range(120):
        # If the server thread already crashed, bail out early
        if _server_error:
            break
        try:
            import urllib.request
            urllib.request.urlopen(url, timeout=1)
            break
        except Exception:
            time.sleep(0.5)
    else:
        # Read log for a detailed error message if available
        detail = _server_error
        if not detail:
            log_path = _log_dir() / "phishx_error.log"
            try:
                detail = log_path.read_text(encoding="utf-8")
            except Exception:
                detail = ""
        msg = "The Phish X server failed to start on port %s." % port
        if detail:
            msg += "\n\nError details:\n" + detail[:800]
        else:
            msg += "\n\nPlease try running the app again."
        _fatal("Phish X – Startup error", msg)

    if _server_error:
        log_path = _log_dir() / "phishx_error.log"
        detail = _server_error[:800]
        _fatal(
            "Phish X – Server crashed",
            "The server crashed during startup.\n\nError:\n%s\n\nFull log: %s" % (detail, log_path),
        )

    try:
        from PyQt6.QtWidgets import QApplication, QMainWindow
        from PyQt6.QtWebEngineWidgets import QWebEngineView
        from PyQt6.QtCore import QUrl
        from PyQt6.QtGui import QIcon
    except ImportError as exc:
        _fatal("Phish X – Missing components", "Required components are missing:\n%s" % exc)

    app_qt = QApplication.instance() or QApplication(sys.argv)
    app_qt.setApplicationName("Phish X")

    # Resolve icon path: works both in development and when frozen by PyInstaller
    if getattr(sys, "frozen", False):
        _icon_path = Path(sys._MEIPASS) / "static" / "favicon.ico"
    else:
        _icon_path = Path(__file__).resolve().parent / "static" / "favicon.ico"

    if _icon_path.exists():
        app_icon = QIcon(str(_icon_path))
        app_qt.setWindowIcon(app_icon)

    window = QMainWindow()
    window.setWindowTitle("Phish X")
    window.setMinimumSize(900, 650)
    window.resize(1100, 750)

    if _icon_path.exists():
        window.setWindowIcon(QIcon(str(_icon_path)))

    browser = QWebEngineView()
    browser.setUrl(QUrl("http://127.0.0.1:%s/static/" % port))
    browser.setZoomFactor(1.0)
    window.setCentralWidget(browser)

    window.show()
    sys.exit(app_qt.exec())


if __name__ == "__main__":
    main()
