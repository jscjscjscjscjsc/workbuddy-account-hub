# -*- coding: utf-8 -*-
"""Ready-first launcher; collection never blocks service binding."""
import os
import sys
import time
import webbrowser
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "server"))
import lifecycle

def main():
    if "--supervise" in sys.argv:
        return lifecycle.supervise()
    port = int(os.environ.get("WBH_PORT") or 8770)
    found = lifecycle.find_service(port)
    if found is not None and (lifecycle.health(found) or {}).get("revision") != lifecycle.REVISION:
        if not lifecycle.stop_service(found):
            print("发现旧版后台但无法安全停止，请点击管理台的停止按钮后再启动。")
            return 1
        deadline = time.monotonic() + 5
        while lifecycle.health(found) and time.monotonic() < deadline:
            time.sleep(.1)
        if lifecycle.health(found):
            print("旧版后台仍在退出，请稍后再双击启动。")
            return 1
        time.sleep(.3)
        found = None
    if found is None:
        lifecycle.spawn_supervisor()
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            found = lifecycle.find_service(port)
            if found is not None:
                break
            time.sleep(0.2)
    if found is None:
        print("管理台未能启动，请查看运行日志/service.log；再次双击可重试。")
        return 1
    url = f"http://127.0.0.1:{found}/"
    print("WorkBuddy 账号管理台已就绪：" + url)
    print("服务独立在后台运行，关闭启动窗口不会停止；账号收录随后自动完成。")
    if "--no-browser" not in sys.argv:
        webbrowser.open(url)
    return 0

if __name__ == "__main__":
    sys.exit(main())
