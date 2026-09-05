from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from passlib.context import CryptContext
from pathlib import Path
import sqlite3, shutil, uuid

BASE = Path(__file__).resolve().parent.parent
DB = BASE / "kyc.db"
UPLOADS = BASE / "uploads"
UPLOADS.mkdir(exist_ok=True)

app = FastAPI(title="Simple KYC Platform")
app.add_middleware(SessionMiddleware, secret_key="CHANGE-THIS-SECRET-IN-PRODUCTION")
app.mount("/static", StaticFiles(directory=BASE/"app/static"), name="static")
templates = Jinja2Templates(directory=BASE/"app/templates")
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

with db() as con:
    con.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
        phone TEXT, password TEXT NOT NULL,
        country TEXT, dob TEXT, document TEXT, selfie TEXT,
        status TEXT DEFAULT 'not_submitted', rejection_reason TEXT
    )""")

def current_user(request):
    uid = request.session.get("uid")
    if not uid: return None
    with db() as con:
        return con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("home.html", {"request":request, "user":current_user(request)})

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request":request})

@app.post("/register")
def register(request: Request, name:str=Form(...), email:str=Form(...), phone:str=Form(""), password:str=Form(...)):
    with db() as con:
        try:
            cur=con.execute("INSERT INTO users(name,email,phone,password) VALUES(?,?,?,?)",
                            (name,email,phone,pwd.hash(password)))
            uid=cur.lastrowid
        except sqlite3.IntegrityError:
            return templates.TemplateResponse("register.html", {"request":request,"error":"این ایمیل قبلاً ثبت شده است."})
    request.session["uid"]=uid
    return RedirectResponse("/kyc", status_code=303)

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request":request})

@app.post("/login")
def login(request: Request, email:str=Form(...), password:str=Form(...)):
    with db() as con:
        u=con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not u or not pwd.verify(password, u["password"]):
        return templates.TemplateResponse("login.html", {"request":request,"error":"ایمیل یا رمز عبور نادرست است."})
    request.session["uid"]=u["id"]
    return RedirectResponse("/dashboard", status_code=303)

@app.get("/kyc", response_class=HTMLResponse)
def kyc_page(request: Request):
    u=current_user(request)
    if not u: return RedirectResponse("/login",303)
    return templates.TemplateResponse("kyc.html", {"request":request,"user":u})

@app.post("/kyc")
def submit_kyc(request: Request, country:str=Form(...), dob:str=Form(...),
               document:UploadFile=File(...), selfie:UploadFile=File(...)):
    u=current_user(request)
    if not u: return RedirectResponse("/login",303)
    uid=u["id"]
    safe_doc=f"{uid}_{uuid.uuid4().hex}_{Path(document.filename).name}"
    safe_selfie=f"{uid}_{uuid.uuid4().hex}_{Path(selfie.filename).name}"
    for upload, name in [(document,safe_doc),(selfie,safe_selfie)]:
        with open(UPLOADS/name,"wb") as out: shutil.copyfileobj(upload.file,out)
    with db() as con:
        con.execute("""UPDATE users SET country=?,dob=?,document=?,selfie=?,
                       status='pending',rejection_reason=NULL WHERE id=?""",
                    (country,dob,safe_doc,safe_selfie,uid))
    return RedirectResponse("/dashboard",303)

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    u=current_user(request)
    if not u: return RedirectResponse("/login",303)
    return templates.TemplateResponse("dashboard.html", {"request":request,"user":u})

@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request):
    # Demo admin login: /admin?key=CHANGE_ME
    if request.query_params.get("key") != "CHANGE_ME":
        return HTMLResponse("<h3>Admin access denied</h3><p>برای نسخه واقعی باید احراز هویت مدیر جداگانه اضافه شود.</p>",403)
    with db() as con: users=con.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    return templates.TemplateResponse("admin.html", {"request":request,"users":users,"key":"CHANGE_ME"})

@app.post("/admin/{uid}/{action}")
def admin_action(request: Request, uid:int, action:str, reason:str=Form("")):
    if request.query_params.get("key") != "CHANGE_ME": return HTMLResponse("Denied",403)
    if action not in ("approve","reject"): return HTMLResponse("Bad action",400)
    status="approved" if action=="approve" else "rejected"
    with db() as con:
        con.execute("UPDATE users SET status=?, rejection_reason=? WHERE id=?",
                    (status, reason if action=="reject" else None, uid))
    return RedirectResponse("/admin?key=CHANGE_ME",303)

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/",303)
