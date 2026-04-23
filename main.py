import os
import uuid
import aiofiles
import json
from typing import Optional, List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.exc import OperationalError, IntegrityError
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import SQLModel, Field, create_engine, Session, select, create_all
from sqlalchemy import create_engine, Column, Integer, String
# from sqlalchemy.orm import Session
import firebase_admin
from firebase_admin import credentials, initialize_app, messaging as fb_messaging
import urllib.parse
from sqlalchemy.exc import IntegrityError, OperationalError
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import shutil
import bcrypt
# Этот хак обманывает passlib, делая вид, что всё на месте
if not hasattr(bcrypt, "__about__"):
    bcrypt.__about__ = type("About", (object,), {"__version__": bcrypt.__version__})

# CONFIG
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 30
UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

# DB
DATABASE_URL = "postgresql://neondb_owner:npg_PnKs5zO9oRBb@ep-fancy-dew-alpa3yx5-pooler.c-3.eu-central-1.aws.neon.tech/neondb?sslmode=require"
engine = create_engine( DATABASE_URL, echo=False, future=True, pool_pre_ping=True, pool_size=5, max_overflow=10, pool_recycle=1800, connect_args={"sslmode": "require"} )

# PASSWORD
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

firebase_config_str = os.environ.get("FIREBASE_JSON")
if firebase_config_str:
    try:
        # 2. Превращаем строку в словарь (JSON)
        firebase_config = json.loads(firebase_config_str)
        # 3. Инициализируем через словарь, а не через файл
        cred = credentials.Certificate(firebase_config)
        initialize_app(cred)
        print("Firebase успешно инициализирован через Environment Variable")
    except Exception as e:
        print(f"Ошибка при чтении FIREBASE_JSON: {e}")
else:
    print("ВНИМАНИЕ: Переменная FIREBASE_JSON не найдена. Пуши работать не будут.")

class FCMTokenUpdate(SQLModel):
    fcm_token: str

@app.post("/update-fcm-token")
async def update_fcm_token(data: FCMTokenUpdate, token: str = Depends(oauth2_scheme)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    uid = int(payload.get("sub"))
    with Session(engine) as s:
        other_users_statement = select(User).where(User.fcm_token == data.fcm_token, User.id != uid)
        other_users = s.execute(other_users_statement).scalars().all()
        for other in other_users:
            other.fcm_token = None
            s.add(other)
        
        # 2. Обновляем токен текущему пользователю
        user = s.get(User, uid)
        if user:
            user.fcm_token = data.fcm_token
            s.add(user)
        
        s.commit()
    return {"status": "ok"}

@app.get("/firebase-messaging-sw.js")
async def get_fcm_sw():
    return FileResponse(
        "firebase-messaging-sw.js", 
        media_type="application/javascript"
    )

@app.get("/manifest.json")
async def get_manifest():
    return FileResponse("manifest.json")

@app.get("/")
def index():
    return FileResponse("static/index.html")

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/sw.js")
async def get_sw():
    return FileResponse("sw.js")

class RoomMember(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True)
    room: str = Field(index=True)

# Models
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    hashed_password: str
    display_name: Optional[str] = Field(default=None)
    fcm_token: Optional[str] = Field(default=None)

class Message(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    sender_id: int
    room: str
    text: Optional[str] = None
    file_path: Optional[str] = None
    display_name: Optional[str] = None,
    created_at: datetime = Field(default_factory=datetime.utcnow)

SQLModel.metadata.create_all(engine)

def verify_token(token: str):
    try:
        # Используйте те же SECRET_KEY и ALGORITHM, что и при создании токена
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        # Если токен подделан или истек
        return None

# Заменяем старый get_password_hash
def get_password_hash(password: str) -> str:
    # Переводим пароль в байты
    pwd_bytes = password.encode('utf-8')
    # Генерируем соль
    salt = bcrypt.gensalt()
    # Хешируем
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    # Возвращаем как строку для базы данных
    return hashed.decode('utf-8')

# Заменяем старый verify_password (пригодится для логина)
def verify_password(plain_password: str, hashed_password: str) -> bool:
    password_byte_enc = plain_password.encode('utf-8')
    hashed_password_enc = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_byte_enc, hashed_password_enc)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user_by_username(username: str):
    with Session(engine) as s:
        return s.query(User).filter(User.username == username).first()

def authenticate_user(username: str, password: str):
    user = get_user_by_username(username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

async def get_current_user(token: str = Depends(lambda: None), authorization: Optional[str] = None):
    raise NotImplementedError

def get_db():
    # Создаем сессию напрямую через engine
    with Session(engine) as session:
        yield session

@app.get("/manifest.json")
async def get_manifest():
    return FileResponse("manifest.json")

@app.get("/me")
def me(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # 1. Проверяем, что функция verify_token существует и работает
    try:
        payload = verify_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Ошибка проверки токена")

    if not payload:
        raise HTTPException(status_code=401, detail="Токен невалиден")

    # 2. Получаем ID (превращаем в число на случай, если в токене строка)
    try:
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="ID не найден в токене")
        user_id = int(user_id) 
    except (ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Неверный формат ID")

    # 3. Ищем пользователя в базе
    user = db.query(User).filter(User.id == user_id).first()

    if user is None:
        raise HTTPException(status_code=401, detail="Пользователь удален из базы")

    return {
        "id": user.id,
        "username": user.username
    }

@app.post("/register") 
def register(
    username: str = Form(...), 
    password: str = Form(...),
    display_name: Optional[str] = Form(None),
    db: Session = Depends(get_db)): 
    try: 
        existing = db.query(User).filter(User.username == username).first()
    except OperationalError: 
        raise HTTPException(status_code=503, detail="База данных временно недоступна")

    if existing:
        raise HTTPException(status_code=400, detail="Это имя пользователя уже занято")

    # Создаем пользователя (используй свою функцию хеширования пароля)
    user = User(username=username, hashed_password=get_password_hash(password))

    if display_name:
        display_name = display_name.strip()
        if len(display_name) > 50:
            raise HTTPException(status_code=400, detail="display_name слишком длинный (макс 50)")

    user = User(
        username=username,
        hashed_password=get_password_hash(password),
        display_name=display_name  # если None — сохранится как NULL
    )

    try:
        db.add(user)
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Ошибка целостности данных")
    except Exception as e:
        db.rollback()
        print(f"Ошибка регистрации: {e}")
        raise HTTPException(status_code=500, detail="Внутренняя ошибка сервера")

    token = create_access_token({"sub": str(user.id), "username": user.username})
    
    return {
        "accesstoken": token, 
        "tokentype": "bearer", 
        "userid": user.id, 
        "username": user.username,
        "display_name": user.display_name
    }

@app.post("/login")
def login(
    username: str = Form(...), 
    password: str = Form(...),
    db: Session = Depends(get_db)): 
    user = db.query(User).filter(User.username == username).first()
    
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")
    
    token = create_access_token({"sub": str(user.id), "username": user.username})
    
    return {
        "accesstoken": token, 
        "tokentype": "bearer", 
        "userid": user.id, 
        "username": user.username
    }

app.mount("/files", StaticFiles(directory=UPLOAD_DIR), name="files")

@app.post("/upload")
async def uploadfile(token: str = Form(...), file: UploadFile = File(...)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        userid = int(payload.get("sub"))
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    ext = os.path.splitext(file.filename)[1]
    filename = f"{uuid.uuid4().hex}{ext}"
    path = os.path.join(UPLOAD_DIR, filename)
    
    async with aiofiles.open(path, 'wb') as out:
        content = await file.read()
        await out.write(content)
    
    return {"file_url": f"/files/{filename}"}

class ConnectionManager:
    def __init__(self):
        self.active: dict[str, list[WebSocket]] = {}

    async def connect(self, room: str, websocket: WebSocket):
        await websocket.accept()
        self.active.setdefault(room, []).append(websocket)

    def disconnect(self, room: str, websocket: WebSocket):
        if room in self.active:
            if websocket in self.active[room]:
                self.active[room].remove(websocket)

    async def broadcast(self, room: str, message: dict):
        if room in self.active:
            for connection in self.active[room]:
                try:
                    await connection.send_json(message)
                except Exception:
                    pass

manager = ConnectionManager()

@app.websocket("/ws/{room}")
async def websocket_endpoint(websocket: WebSocket, room: str, token: str = None):
    # 1. Подключаемся через менеджер (там внутри accept)
    await manager.connect(room, websocket)
    print(f"--- [WS OPEN] Room: {room} ---")

    try:
        # 2. Проверка токена
        if not token:
            print("Ошибка: Токен отсутствует")
            await websocket.close(code=1008)
            return

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        userid = int(payload.get("sub"))

        with Session(engine) as s:
            existing = s.exec(select(RoomMember).where(RoomMember.user_id == userid, RoomMember.room == room)).first()
            if not existing:
                s.add(RoomMember(user_id=userid, room=room))
                s.commit()
        
        # 3. Получаем display_name (безопасно)
        display_name = ""
        try:
            with Session(engine) as s:
                user = s.get(User, userid) 
                if user:
                    # Берем display_name, если нет - логин, если нет - пусто
                    display_name = getattr(user, 'display_name', '') or getattr(user, 'username', '') or ""
        except Exception as db_e:
            print(f"Ошибка получения имени из БД: {db_e}")

        # 4. ЦИКЛ СООБЩЕНИЙ
        while True:
            try:
                # Ждем данные
                data = await websocket.receive_json()
                print(f"Получены данные: {data}")
            except Exception as e:
                print(f"Ошибка receive_json (клиент закрыл вкладку?): {e}")
                break

            text = data.get("text")
            file_url_from_js = data.get("file_url")

            # 5. СОХРАНЕНИЕ В БАЗУ (с защитой от вылета)
            new_id = 0
            iso_date = datetime.utcnow().isoformat()
            
            try:
                msg = Message(
                    sender_id=userid,
                    room=room,
                    text=text,
                    file_path=file_url_from_js
                )
                with Session(engine) as s:
                    s.add(msg)
                    s.commit()
                    s.refresh(msg)
                    new_id = msg.id
                    if msg.created_at:
                        iso_date = msg.created_at.isoformat()
            except Exception as db_save_e:
                print(f"ОШИБКА СОХРАНЕНИЯ В БД: {db_save_e}")
                # Даже если БД упала, сообщение отправим в чат (без сохранения)
                new_id = 999 

            # 6. РАССЫЛКА (Broadcast)
            out_payload = {
                "id": new_id,
                "sender_id": userid,
                "display_name": display_name,
                "room": room,
                "text": text,
                "file_url": file_url_from_js,
                "created_at": iso_date
            }
            
            print(f"Рассылка сообщения: {out_payload}")
            await manager.broadcast(room, out_payload)

            try:
                await send_push_notification(room, display_name, text, exclude_id=userid)
                print(f"Пуш-уведомление отправлено для комнаты {room}")
            except Exception as push_e:
                print(f"Ошибка при отправке пуша: {push_e}")

    except WebSocketDisconnect:
        print(f"--- [WS DISCONNECT] Room: {room} ---")
    except Exception as global_e:
        print(f"ГЛОБАЛЬНАЯ ОШИБКА WS: {global_e}")
    finally:
        manager.disconnect(room, websocket)

async def send_push_notification(room, sender_name, text, exclude_id=None):
    try:
        with Session(engine) as s:
            statement = (
                select(User)
                .join(RoomMember, User.id == RoomMember.user_id)
                .where(RoomMember.room == str(room))
                .where(User.fcm_token != None)
            )
            if exclude_id is not None:
                statement = statement.where(User.id != exclude_id)
            
            results = s.execute(statement)
            users = results.scalars().all()

            if not users:
                return

            unique_tokens = {u.fcm_token: u.id for u in users} 

            for token, user_id in unique_tokens.items():
                try:
                    message = fb_messaging.Message(
                        notification=fb_messaging.Notification(
                            title=f"{sender_name}",
                            body=text if text else "Прислал(а) файл"
                        ),
                        data={
                            "room": str(room),
                            "click_action": f"/?room={room}"
                        },
                        # Настройки для Android (чтобы телефон "проснулся")
                        android=fb_messaging.AndroidConfig(
                            priority='high',
                            notification=fb_messaging.AndroidNotification(
                                click_action="TOP_STORY_ACTIVITY" # Для системной обработки
                            )
                        ),
                        webpush=fb_messaging.WebpushConfig(
                        headers={"Urgency": "high"},
                    notification=fb_messaging.WebpushNotification(
                    icon="/static/1.png",
                    badge="/static/1.png",
                    tag="tegeshka-msg"
                    ),
                            fcm_options=fb_messaging.WebpushFCMOptions(
                                link=f"https://tegeshka.onrender.com/?room={room}"
                            )
                        ),
                        token=token
                    )
                    fb_messaging.send(message)
                    print(f"Пуш успешно отправлен на токен пользователя {user_id}")
                
                except Exception as e:
                    err_text = str(e).lower()
                    if "not-registered" in err_text or "unregistered" in err_text:
                        print(f"Токен пользователя {user_id} протух. Удаляем.")
                        # Очищаем токен в базе у этого конкретного юзера
                        user_to_clean = s.get(User, user_id)
                        if user_to_clean:
                            user_to_clean.fcm_token = None
                            s.add(user_to_clean)
                            s.commit()
    except Exception as e:
        print(f"Критическая ошибка в функции пуша: {e}")