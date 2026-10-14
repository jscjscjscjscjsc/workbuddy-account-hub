"""Real detached-process restart test in a temporary project, with background mutations off."""
import hashlib,json,os
from pathlib import Path
import shutil,signal,socket,subprocess,sys,tempfile,time,urllib.request
ROOT=Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix="wbh-boot-proof-") as temp:
    fixture=Path(temp)/"管理台";fixture.mkdir();(fixture/"server").mkdir()
    for name in ("launch.py","index.html","server/server.py","server/vault.py","server/lifecycle.py","server/phone_login.py","server/wbkey.js"):
        shutil.copy2(ROOT/name,fixture/name)
    home=Path(temp)/"home";home.mkdir()
    project=hashlib.sha256(str(fixture.resolve()).casefold().encode()).hexdigest()[:16]
    busy=socket.socket();busy.bind(("127.0.0.1",0));busy.listen()
    base=busy.getsockname()[1]
    env={**os.environ,"WBH_PORT":str(base),"WBH_HOME":str(home),"WBH_VAULT_DIR":str(Path(temp)/"vault"),"WBH_BACKGROUND":"0","PYTHONUTF8":"1","PYTHONIOENCODING":"utf-8"}
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def health(port):
        try:
            with opener.open(f"http://127.0.0.1:{port}/api/health",timeout=.2) as r:v=json.load(r)
            return v if v.get("project")==project else None
        except Exception:return None
    port=None
    try:
        result=subprocess.run([sys.executable,"-X","utf8",str(fixture/"launch.py"),"--no-browser"],env=env,capture_output=True,encoding="utf-8",timeout=40)
        assert result.returncode==0,result.stdout+result.stderr
        port=json.loads((fixture/"运行日志/service.json").read_text(encoding="utf-8"))["port"]
        first=health(port);assert first and port!=base
        print("PASS: parent launcher exited; detached service alive on actual fallback port",flush=True)
        repeat=subprocess.run([sys.executable,str(fixture/"launch.py"),"--no-browser"],env=env,capture_output=True,timeout=20)
        assert repeat.returncode==0 and health(port)["pid"]==first["pid"]
        print("PASS: repeated launch reuses the same healthy service",flush=True)
        # Only the fixture child is terminated; identity is verified above.
        os.kill(first["pid"],signal.SIGTERM)
        deadline=time.monotonic()+15;second=None
        while time.monotonic()<deadline:
            second=health(port)
            if second and second["pid"]!=first["pid"]:break
            time.sleep(.2)
        assert second and second["pid"]!=first["pid"]
        print("PASS: supervisor recovered from a real child-process crash",flush=True)
    finally:
        busy.close()
        if port is not None and health(port):
            req=urllib.request.Request(f"http://127.0.0.1:{port}/api/service-stop",data=b"{}",headers={"Content-Type":"application/json"},method="POST")
            with opener.open(req,timeout=3) as r:assert json.load(r)["ok"]
            deadline=time.monotonic()+5
            while health(port) and time.monotonic()<deadline:time.sleep(.1)
            assert not health(port)
            time.sleep(.3)
            print("PASS: explicit stop ends the fixture service without a restart",flush=True)
