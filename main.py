import os
from datetime import timedelta, datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import jwt

from database import db

SECRET_KEY = os.getenv("JWT_SECRET", "dev-secret-change")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class SignupModel(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginModel(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

app = FastAPI()

# CORS configuration: allow all origins by default to simplify previews and Netlify builds
# Tighten this in production by setting FRONTEND_URL or CORS_ORIGIN_REGEX
allow_all = os.getenv("CORS_ALLOW_ALL", "true").lower() == "true"
frontend_env = os.getenv("FRONTEND_URL")
origin_regex = os.getenv("CORS_ORIGIN_REGEX")

if allow_all and not origin_regex:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    origins = [
        "http://localhost:3000",
        "https://localhost:3000",
    ]
    if frontend_env:
        origins.append(frontend_env)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_origin_regex=origin_regex,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI Backend!"}

@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response

# Simple helpers

def get_user_by_email(email: str) -> Optional[dict]:
    return db["authuser"].find_one({"email": email}) if db else None

@app.post("/auth/signup")
def signup(payload: SignupModel):
    if not db:
        raise HTTPException(status_code=500, detail="Database not configured")
    if db["authuser"].find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    password_hash = pwd_context.hash(payload.password)
    doc = {"name": payload.name, "email": payload.email, "password_hash": password_hash}
    db["authuser"].insert_one(doc)
    return {"message": "User created"}

@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginModel):
    if not db:
        raise HTTPException(status_code=500, detail="Database not configured")
    user = db["authuser"].find_one({"email": payload.email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not pwd_context.verify(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": str(user["_id"]), "email": user["email"], "exp": expire}
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return TokenResponse(access_token=token)

@app.get("/auth/me")
def me(request: Request):
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = auth.split(" ")[1]
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db["authuser"].find_one({"email": data.get("email")}) if db else None
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"email": user["email"], "name": user.get("name", "")}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
