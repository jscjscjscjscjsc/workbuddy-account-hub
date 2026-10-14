"""User-triggered SMS login; credentials are encrypted into the local vault only."""
import base64,json,os,re,threading,time,urllib.request,urllib.error,zipfile
import vault
LOCK=threading.Lock()
PENDING={}
SMS_JOBS={}

def request(path,body):
    req=urllib.request.Request("https://www.workbuddy.cn"+path,
        data=json.dumps(body).encode(),method="POST",headers={"Content-Type":"application/json","Accept":"application/json","Origin":"https://www.workbuddy.cn","Referer":"https://www.workbuddy.cn/","User-Agent":"Mozilla/5.0"})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({})) if os.environ.get("WBH_LOGIN_USE_PROXY")!="1" else urllib.request.build_opener()
    try:
        with opener.open(req,timeout=15) as response:
            value=json.load(response)
    except urllib.error.HTTPError as error:
        raise ValueError("官方登录接口返回 HTTP %s，请稍后重试" % error.code) from None
    except (TimeoutError,urllib.error.URLError):
        raise ValueError("官方接口响应超时；若已收到短信请直接验证，避免重复发送") from None
    if value.get("code")!=0:
        raise ValueError(str(value.get("msg") or "官方验证失败，请重试")[:200])
    return value.get("data") or {}

def phone_number(value):
    value=str(value or "").strip()
    if not re.fullmatch(r"1[3-9]\d{9}",value):raise ValueError("请输入有效的 11 位中国大陆手机号")
    return value

def send(phone):
    phone=phone_number(phone)
    with LOCK:
        previous=PENDING.get(phone,0)
        if time.monotonic()-previous<60: return {"ok":False,"reason":"请等待 60 秒后再发送"}
        PENDING[phone]=time.monotonic()
    try:
        request("/v2/plugin/login/send-sms",{"phone":phone})
    except Exception:
        with LOCK:PENDING.pop(phone,None)
        raise
    return {"ok":True,"reason":"验证码已发送，请在 5 分钟内验证","retryAfter":60}


def begin_send(phone):
    phone=phone_number(phone)
    with LOCK:
        job=SMS_JOBS.get(phone)
        if job and (job.get("pending") or time.monotonic()-job["started"]<60):
            return {k:v for k,v in job.items() if k!="started"}
        job={"ok":True,"pending":True,"reason":"正在请求官方短信接口…","started":time.monotonic()}
        SMS_JOBS[phone]=job
        for key in list(SMS_JOBS):
            if not SMS_JOBS[key].get("pending") and time.monotonic()-SMS_JOBS[key]["started"]>300:
                del SMS_JOBS[key]
    def worker():
        try:
            result=send(phone)
        except Exception as error:
            result={"ok":False,"reason":str(error)[:200]}
        with LOCK:
            job.update(result,pending=False)
            if not result.get("ok"):job["started"]=0
    threading.Thread(target=worker,daemon=True).start()
    return {"ok":True,"pending":True,"reason":"正在请求官方短信接口…"}


def sms_status(phone):
    phone=phone_number(phone)
    with LOCK:
        job=SMS_JOBS.get(phone)
        return ({k:v for k,v in job.items() if k!="started"} if job else
                {"ok":False,"pending":False,"reason":"发送状态已失效，请确认短信是否收到"})

def claims(token):
    segment=token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(segment+"="*(-len(segment)%4)))

@vault.serialized_mutation
def save_verified(phone,data):
    access=data.get("accessToken") or data.get("access_token")
    refresh=data.get("refreshToken") or data.get("refresh_token")
    if not access or not refresh:raise ValueError("官方响应缺少登录凭据，未保存账号")
    payload=claims(access);uid=payload.get("sub")
    if not uid or not vault._UUID.fullmatch(uid) or payload.get("exp",0)*1000<=vault.now_ms():
        raise ValueError("官方登录凭据无效，未保存账号")
    username=str(payload.get("preferred_username") or "")
    if re.fullmatch(r"1[3-9]\d{9}",username) and username!=phone:
        raise ValueError("验证账号与填写手机号不一致")
    secret,error=vault._secret_or_error()
    if error:raise ValueError(error)
    now=vault.now_ms()
    account=dict(data.get("account") or {})
    account.update({"uid":uid,"nickname":vault.wb_wrap_field(secret,phone),"phoneNumber":vault.wb_wrap_field(secret,phone),"type":account.get("type") or "personal"})
    auth={"accessToken":vault.wb_wrap_field(secret,access),"refreshToken":vault.wb_wrap_field(secret,refresh),
          "tokenType":data.get("tokenType") or "Bearer","domain":"https://www.workbuddy.cn",
          "expiresAt":payload["exp"]*1000,"lastRefreshTime":now}
    if data.get("refreshExpiresIn"):auth["refreshExpiresAt"]=now+int(data["refreshExpiresIn"])*1000
    document={"account":account,"auth":auth}
    snapshot={"primary":{"uid":uid,"nickname":phone,"type":account["type"],"savedAt":now}}
    dest=vault.snapshot_path(uid,phone);temp=dest+".sms.tmp"
    existing=vault.find_entry(uid) or {}
    try:
        # Keep prior ancillary files when renewing an already collected account.
        with zipfile.ZipFile(temp,"w",zipfile.ZIP_DEFLATED) as out:
            if os.path.isfile(existing.get("zip") or ""):
                with zipfile.ZipFile(existing["zip"]) as old:
                    for name in old.namelist():
                        if name not in ("@auth/workbuddy-desktop.info","storage/skeleton/account-snapshot.json"):
                            out.writestr(name,old.read(name))
            out.writestr("@auth/workbuddy-desktop.info",json.dumps(document,ensure_ascii=False).encode())
            out.writestr("storage/skeleton/account-snapshot.json",json.dumps(snapshot,ensure_ascii=False).encode())
        os.replace(temp,dest)
    finally:
        if os.path.exists(temp):os.remove(temp)
    vault.upsert_entry(uid,{"nickname":phone,"hasSession":True,"hasCookies":bool(existing.get("hasCookies")),"collectedAt":now,"source":"手机号首次验证登录"})
    return {"ok":True,"uid":uid,"reason":"验证成功，账号已加密保存；当前 WorkBuddy 登录身份保持不变"}

def verify(phone,code):
    phone=phone_number(phone);code=str(code or "").strip()
    if not re.fullmatch(r"\d{4,8}",code):raise ValueError("请输入收到的短信验证码")
    with LOCK:
        sent=PENDING.get(phone)
        # A service restart or an upstream timeout must not discard an SMS
        # already delivered. The official token endpoint validates the code.
        if sent and time.monotonic()-sent>300:raise ValueError("验证码已过期，请重新发送")
    data=request("/v2/plugin/login/token",{"login_method":"phone","phone":phone,"sms_code":code})
    result=save_verified(phone,data)
    if result.get("ok"):
        with LOCK:PENDING.pop(phone,None)
    return result
