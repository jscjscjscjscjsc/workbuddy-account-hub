"""Portable Windows entry point; also dispatches detached child modes."""
import ctypes
from pathlib import Path
import sys

ROOT = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "server"))


def main():
    if "--serve" in sys.argv:
        import server
        return server.main()
    import launch
    return launch.main()


if __name__ == "__main__":
    try:
        code = main()
        if code and "--supervise" not in sys.argv and "--serve" not in sys.argv:
            ctypes.windll.user32.MessageBoxW(None, "管理台启动失败，请查看程序目录中的运行日志。", "WorkBuddy 账号管理台", 16)
    except Exception as error:
        if "--supervise" not in sys.argv and "--serve" not in sys.argv:
            ctypes.windll.user32.MessageBoxW(None, "启动失败：" + str(error), "WorkBuddy 账号管理台", 16)
        raise
    sys.exit(code)
