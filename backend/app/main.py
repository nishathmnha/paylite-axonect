import csv
import io
import logging
import os
import uuid
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import (Boolean, DateTime, ForeignKey, Numeric, String, UniqueConstraint,
                        create_engine, func, select)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship

logging.basicConfig(level=logging.INFO, format='%(message)s')
log = logging.getLogger('paylite')
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./paylite.db')
SECRET = os.getenv('JWT_SECRET', 'local-development-secret')
LIMIT = Decimal(os.getenv('DAILY_TRANSFER_LIMIT', '10000'))
pwd = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth = OAuth2PasswordBearer(tokenUrl='/api/auth/login')
engine = create_engine(DATABASE_URL, pool_pre_ping=True)

class Base(DeclarativeBase): pass

class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    mobile: Mapped[str] = mapped_column(String(30), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    pin_hash: Mapped[str] = mapped_column(String(255))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_pin_attempts: Mapped[int] = mapped_column(default=0)
    pin_locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class Wallet(Base):
    __tablename__ = 'wallets'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), unique=True)
    balance: Mapped[Decimal] = mapped_column(Numeric(12, 2), default=0)

class Transfer(Base):
    __tablename__ = 'transfers'
    id: Mapped[int] = mapped_column(primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    recipient_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    amount: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    idempotency_key: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(20), default='completed')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    reversed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    __table_args__ = (UniqueConstraint('sender_id', 'idempotency_key', name='uq_transfer_idem'),)

class LedgerEntry(Base):
    __tablename__ = 'ledger_entries'
    id: Mapped[int] = mapped_column(primary_key=True)
    wallet_id: Mapped[int] = mapped_column(ForeignKey('wallets.id'), index=True)
    kind: Mapped[str] = mapped_column(String(20))
    amount: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    reference: Mapped[str] = mapped_column(String(100))
    balance_after: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

Base.metadata.create_all(engine)

with Session(engine) as _seed:
    if not _seed.scalar(select(User).where(User.mobile == '9999999999')):
        _admin = User(name='Demo Admin', mobile='9999999999',
                      password_hash=pwd.hash('Admin123!'), pin_hash=pwd.hash('1234'), is_admin=True)
        _seed.add(_admin); _seed.flush(); _seed.add(Wallet(user_id=_admin.id)); _seed.commit()

class RegisterIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    mobile: str = Field(min_length=3, max_length=30)
    password: str = Field(min_length=8)
    pin: str = Field(pattern=r'^\d{4,6}$')

class TopupIn(BaseModel):
    amount: Decimal = Field(gt=0, le=5000)

class TransferIn(BaseModel):
    recipient_mobile: str
    amount: Decimal = Field(gt=0, le=100000)
    pin: str = Field(pattern=r'^\d{4,6}$')

class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int; name: str; mobile: str; is_admin: bool

def db():
    with Session(engine) as s:
        yield s

def token(user: User) -> str:
    return jwt.encode({'sub': str(user.id), 'exp': datetime.now(timezone.utc) + timedelta(hours=8)}, SECRET, algorithm='HS256')

def current_user(t: Annotated[str, Depends(oauth)], s: Session = Depends(db)) -> User:
    try: uid = int(jwt.decode(t, SECRET, algorithms=['HS256'])['sub'])
    except (JWTError, KeyError, ValueError): raise HTTPException(401, 'Invalid or expired token')
    user = s.get(User, uid)
    if not user: raise HTTPException(401, 'User not found')
    return user

def write_ledger(s: Session, wallet: Wallet, kind: str, amount: Decimal, ref: str):
    wallet.balance = (wallet.balance or Decimal('0')) + amount
    if wallet.balance < 0: raise HTTPException(409, 'Insufficient balance')
    s.add(LedgerEntry(wallet_id=wallet.id, kind=kind, amount=amount, reference=ref, balance_after=wallet.balance))

app = FastAPI(title='PayLite API')
app.add_middleware(CORSMiddleware, allow_origins=['http://localhost:5173'], allow_methods=['*'], allow_headers=['*'])

@app.middleware('http')
async def correlation(request: Request, call_next):
    cid = request.headers.get('X-Correlation-ID', str(uuid.uuid4()))
    response = await call_next(request); response.headers['X-Correlation-ID'] = cid
    log.info('%s %s %s %s', cid, request.method, request.url.path, response.status_code)
    return response

@app.get('/api/health')
def health(): return {'status': 'ok'}

@app.post('/api/auth/register', response_model=UserOut, status_code=201)
def register(x: RegisterIn, s: Session = Depends(db)):
    if s.scalar(select(User).where(User.mobile == x.mobile)): raise HTTPException(409, 'Mobile number already registered')
    u = User(name=x.name, mobile=x.mobile, password_hash=pwd.hash(x.password), pin_hash=pwd.hash(x.pin))
    s.add(u); s.flush(); s.add(Wallet(user_id=u.id)); s.commit(); s.refresh(u); return u

@app.post('/api/auth/login')
def login(form: Annotated[OAuth2PasswordRequestForm, Depends()], s: Session = Depends(db)):
    u = s.scalar(select(User).where(User.mobile == form.username))
    if not u or not pwd.verify(form.password, u.password_hash): raise HTTPException(401, 'Invalid mobile or password')
    return {'access_token': token(u), 'token_type': 'bearer', 'user': UserOut.model_validate(u, from_attributes=True)}

@app.get('/api/me', response_model=UserOut)
def me(u: User = Depends(current_user)): return u

@app.get('/api/wallet')
def wallet(u: User = Depends(current_user), s: Session = Depends(db)):
    w = s.scalar(select(Wallet).where(Wallet.user_id == u.id)); return {'balance': w.balance}

@app.post('/api/wallet/topup')
def topup(x: TopupIn, u: User = Depends(current_user), s: Session = Depends(db)):
    w = s.scalar(select(Wallet).where(Wallet.user_id == u.id)); write_ledger(s, w, 'topup', x.amount, 'topup'); s.commit(); return {'balance': w.balance}

@app.post('/api/transfers')
def transfer(x: TransferIn, idempotency_key: Annotated[str | None, Header()] = None, u: User = Depends(current_user), s: Session = Depends(db)):
    if not idempotency_key: raise HTTPException(400, 'Idempotency-Key header is required')
    old = s.scalar(select(Transfer).where(Transfer.sender_id == u.id, Transfer.idempotency_key == idempotency_key))
    if old: return {'id': old.id, 'status': old.status, 'amount': old.amount}
    if u.pin_locked_until and u.pin_locked_until > datetime.now(timezone.utc): raise HTTPException(423, 'PIN temporarily locked')
    if not pwd.verify(x.pin, u.pin_hash):
        u.failed_pin_attempts += 1
        if u.failed_pin_attempts >= 3: u.pin_locked_until = datetime.now(timezone.utc) + timedelta(minutes=15); u.failed_pin_attempts = 0
        s.commit(); raise HTTPException(401, 'Invalid PIN')
    u.failed_pin_attempts = 0
    recipient = s.scalar(select(User).where(User.mobile == x.recipient_mobile))
    if not recipient: raise HTTPException(404, 'Recipient not found')
    if recipient.id == u.id: raise HTTPException(400, 'Cannot transfer to yourself')
    start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    sent = s.scalar(select(func.coalesce(func.sum(Transfer.amount), 0)).where(Transfer.sender_id == u.id, Transfer.created_at >= start, Transfer.status == 'completed')) or 0
    if Decimal(sent) + x.amount > LIMIT: raise HTTPException(409, f'Daily limit exceeded; remaining {LIMIT - Decimal(sent):.2f}')
    wallet_rows = list(s.scalars(select(Wallet).where(Wallet.user_id.in_([u.id, recipient.id])).order_by(Wallet.id).with_for_update()))
    by_user = {w.user_id: w for w in wallet_rows}
    sender_w, recipient_w = by_user[u.id], by_user[recipient.id]
    if sender_w.balance < x.amount: raise HTTPException(409, 'Insufficient balance')
    t = Transfer(sender_id=u.id, recipient_id=recipient.id, amount=x.amount, idempotency_key=idempotency_key)
    s.add(t); s.flush(); write_ledger(s, sender_w, 'sent', -x.amount, str(t.id)); write_ledger(s, recipient_w, 'received', x.amount, str(t.id)); s.commit()
    return {'id': t.id, 'status': t.status, 'amount': t.amount}

@app.get('/api/statement')
def statement(u: User = Depends(current_user), s: Session = Depends(db), from_date: date | None = None, to_date: date | None = None, csv_export: bool = False):
    w = s.scalar(select(Wallet).where(Wallet.user_id == u.id)); q = select(LedgerEntry).where(LedgerEntry.wallet_id == w.id).order_by(LedgerEntry.created_at.desc())
    rows = list(s.scalars(q));
    if from_date: rows = [r for r in rows if r.created_at.date() >= from_date]
    if to_date: rows = [r for r in rows if r.created_at.date() <= to_date]
    data = [{'id': r.id, 'type': r.kind, 'amount': r.amount, 'balance': r.balance_after, 'reference': r.reference, 'timestamp': r.created_at} for r in rows]
    if csv_export:
        out = io.StringIO(); writer = csv.DictWriter(out, fieldnames=data[0].keys() if data else ['id','type','amount','balance','reference','timestamp']); writer.writeheader(); writer.writerows(data)
        return Response(out.getvalue(), media_type='text/csv', headers={'Content-Disposition': 'attachment; filename=statement.csv'})
    return data

@app.post('/api/admin/transfers/{transfer_id}/reverse')
def reverse(transfer_id: int, u: User = Depends(current_user), s: Session = Depends(db)):
    if not u.is_admin: raise HTTPException(403, 'Admin access required')
    t = s.get(Transfer, transfer_id)
    if not t: raise HTTPException(404, 'Transfer not found')
    if t.status == 'reversed': raise HTTPException(409, 'Transfer already reversed')
    recipient_w = s.scalar(select(Wallet).where(Wallet.user_id == t.recipient_id).with_for_update())
    sender_w = s.scalar(select(Wallet).where(Wallet.user_id == t.sender_id).with_for_update())
    if recipient_w.balance < t.amount: raise HTTPException(409, 'Recipient has insufficient balance for reversal')
    write_ledger(s, recipient_w, 'reversal', -t.amount, str(t.id)); write_ledger(s, sender_w, 'reversal', t.amount, str(t.id)); t.status = 'reversed'; t.reversed_at = datetime.now(timezone.utc); s.commit(); return {'status': t.status}
