"""ShopLink pilot API. Payment provider and dispatch are explicitly simulated."""
import hashlib, hmac, os, secrets, time, uuid
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from typing import Optional
import jwt
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, String, Integer, ForeignKey, UniqueConstraint
from sqlalchemy.orm import declarative_base, sessionmaker, Session

DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./shoplink.db')
JWT_SECRET = os.getenv('JWT_SECRET', 'LOCAL_DEVELOPMENT_ONLY_CHANGE_ME')
if os.getenv('ENVIRONMENT') == 'production' and JWT_SECRET == 'LOCAL_DEVELOPMENT_ONLY_CHANGE_ME':
    raise RuntimeError('Set JWT_SECRET before running in production')
engine = create_engine(DATABASE_URL, connect_args={'check_same_thread': False} if DATABASE_URL.startswith('sqlite') else {})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__='users'
    id=Column(String, primary_key=True); name=Column(String,nullable=False); phone=Column(String,unique=True,nullable=False); salt=Column(String,nullable=False); password_hash=Column(String,nullable=False); role=Column(String,nullable=False,default='CUSTOMER')
class Store(Base):
    __tablename__='stores'
    id=Column(String,primary_key=True); name=Column(String,nullable=False); location=Column(String,nullable=False)
class Product(Base):
    __tablename__='products'
    id=Column(String,primary_key=True); store_id=Column(String,ForeignKey('stores.id')); name=Column(String,nullable=False); price_cents=Column(Integer,nullable=False); stock=Column(Integer,nullable=False)
class CartItem(Base):
    __tablename__='cart_items'
    id=Column(String,primary_key=True); user_id=Column(String,ForeignKey('users.id')); product_id=Column(String,ForeignKey('products.id')); quantity=Column(Integer,nullable=False)
    __table_args__=(UniqueConstraint('user_id','product_id'),)
class Order(Base):
    __tablename__='orders'
    id=Column(String,primary_key=True); user_id=Column(String,ForeignKey('users.id')); store_id=Column(String,ForeignKey('stores.id')); status=Column(String,nullable=False); merchandise_cents=Column(Integer,nullable=False); delivery_cents=Column(Integer,nullable=False,default=20000); recipient_address=Column(String,nullable=False); created_at=Column(String,nullable=False); idempotency_key=Column(String,nullable=False)
    __table_args__=(UniqueConstraint('user_id','idempotency_key'),)
class OrderLine(Base):
    __tablename__='order_lines'
    id=Column(String,primary_key=True); order_id=Column(String,ForeignKey('orders.id')); product_id=Column(String,ForeignKey('products.id')); quantity=Column(Integer,nullable=False); price_cents=Column(Integer,nullable=False)
class Payment(Base):
    __tablename__='payments'
    id=Column(String,primary_key=True); order_id=Column(String,ForeignKey('orders.id'),unique=True); status=Column(String,nullable=False); amount_cents=Column(Integer,nullable=False); provider=Column(String,nullable=False)
class Delivery(Base):
    __tablename__='deliveries'
    id=Column(String,primary_key=True); order_id=Column(String,ForeignKey('orders.id'),unique=True); rider_id=Column(String,nullable=True); status=Column(String,nullable=False); otp_hash=Column(String,nullable=True)
class Event(Base):
    __tablename__='events'
    id=Column(String,primary_key=True); order_id=Column(String,nullable=False); event_type=Column(String,nullable=False); detail=Column(String,nullable=False); created_at=Column(String,nullable=False)

Base.metadata.create_all(engine)
app=FastAPI(title='ShopLink Kenya Pilot API',version='0.1.0',description='Runnable pilot subset of the proposed OpenAPI v2 contract. Provider integrations are simulated.')
bearer=HTTPBearer()

def db_session():
    db=SessionLocal()
    try: yield db
    finally: db.close()
def now(): return datetime.now(timezone.utc).isoformat()
def new_id(prefix):return prefix+'_'+uuid.uuid4().hex[:16]
def hash_password(password,salt):return hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),250000).hex()
def token(user):return jwt.encode({'sub':user.id,'role':user.role,'exp':int(time.time())+3600},JWT_SECRET,algorithm='HS256')
def current_user(credentials:HTTPAuthorizationCredentials=Depends(bearer),db:Session=Depends(db_session)):
    try: data=jwt.decode(credentials.credentials,JWT_SECRET,algorithms=['HS256']); user=db.get(User,data['sub'])
    except (jwt.PyJWTError,KeyError):raise HTTPException(401,'Invalid or expired token')
    if not user:raise HTTPException(401,'Unknown user')
    return user
def require(*roles):
    def check(user:User=Depends(current_user)):
        if user.role not in roles:raise HTTPException(403,'Insufficient role')
        return user
    return check
def audit(db,order_id,event_type,detail=''):
    db.add(Event(id=new_id('evt'),order_id=order_id,event_type=event_type,detail=detail,created_at=now()))
def cents(value):return int((Decimal(str(value))*100).quantize(Decimal('1'),rounding=ROUND_HALF_UP))
def money(value):return str((Decimal(value)/100).quantize(Decimal('0.01')))
def order_view(order):return {'id':order.id,'storeId':order.store_id,'status':order.status,'merchandiseKES':money(order.merchandise_cents),'deliveryKES':money(order.delivery_cents),'totalKES':money(order.merchandise_cents+order.delivery_cents),'recipientAddress':order.recipient_address}
class Register(BaseModel):
    name:str=Field(min_length=2);phone:str=Field(pattern=r'^\+254\d{9}$');password:str=Field(min_length=10)
class Login(BaseModel):phone:str;password:str
class AddCart(BaseModel):productId:str;quantity:int=Field(ge=1,le=100)
class CreateOrder(BaseModel):recipientAddress:str=Field(min_length=5)
class Pay(BaseModel):orderId:str;phone:str=Field(pattern=r'^\+254\d{9}$')
class UpdateStatus(BaseModel):status:str
class Assign(BaseModel):riderId:str=Field(min_length=1)
class Proof(BaseModel):otp:str
class StockUpdate(BaseModel):productId:str;stock:int=Field(ge=0)

@app.get('/health')
def health():return {'status':'ok','paymentMode':'SIMULATED'}
@app.post('/v1/auth/register',status_code=201)
def register(body:Register,db:Session=Depends(db_session)):
    if db.query(User).filter_by(phone=body.phone).first():raise HTTPException(409,'Phone already registered')
    salt=secrets.token_hex(16);user=User(id=new_id('usr'),name=body.name,phone=body.phone,salt=salt,password_hash=hash_password(body.password,salt),role='CUSTOMER');db.add(user);db.commit();return {'accessToken':token(user),'tokenType':'bearer','userId':user.id}
@app.post('/v1/auth/login')
def login(body:Login,db:Session=Depends(db_session)):
    user=db.query(User).filter_by(phone=body.phone).first()
    if not user or not hmac.compare_digest(user.password_hash,hash_password(body.password,user.salt)):raise HTTPException(401,'Invalid credentials')
    return {'accessToken':token(user),'tokenType':'bearer','userId':user.id}
@app.get('/v1/customers/me')
def me(user:User=Depends(current_user)):return {'id':user.id,'name':user.name,'phone':user.phone,'role':user.role}
@app.get('/v1/stores')
def stores(db:Session=Depends(db_session)):return [{'id':s.id,'name':s.name,'location':s.location} for s in db.query(Store).all()]
@app.get('/v1/stores/{storeId}/products')
def products(storeId:str,db:Session=Depends(db_session)):
    if not db.get(Store,storeId):raise HTTPException(404,'Store not found')
    return [{'id':p.id,'name':p.name,'priceKES':money(p.price_cents),'available':p.stock>0,'stock':p.stock} for p in db.query(Product).filter_by(store_id=storeId).all()]
@app.post('/v1/cart/items',status_code=201)
def add_cart(body:AddCart,user:User=Depends(require('CUSTOMER')),db:Session=Depends(db_session)):
    product=db.get(Product,body.productId)
    if not product:raise HTTPException(404,'Product not found')
    item=db.query(CartItem).filter_by(user_id=user.id,product_id=product.id).first()
    qty=body.quantity+(item.quantity if item else 0)
    if qty>product.stock:raise HTTPException(409,'Insufficient stock')
    if item:item.quantity=qty
    else:item=CartItem(id=new_id('cart'),user_id=user.id,product_id=product.id,quantity=qty);db.add(item)
    db.commit();return {'itemId':item.id,'quantity':item.quantity}
@app.get('/v1/cart')
def cart(user:User=Depends(require('CUSTOMER')),db:Session=Depends(db_session)):
    items=db.query(CartItem).filter_by(user_id=user.id).all();return {'items':[{'id':i.id,'productId':i.product_id,'quantity':i.quantity} for i in items]}
@app.post('/v1/orders',status_code=201)
def create_order(body:CreateOrder,idempotency_key:str=Header(...,alias='Idempotency-Key'),user:User=Depends(require('CUSTOMER')),db:Session=Depends(db_session)):
    if len(idempotency_key)>128:raise HTTPException(422,'Idempotency key too long')
    existing=db.query(Order).filter_by(user_id=user.id,idempotency_key=idempotency_key).first()
    if existing:return order_view(existing)
    items=db.query(CartItem).filter_by(user_id=user.id).all()
    if not items:raise HTTPException(400,'Cart is empty')
    products=[db.get(Product,i.product_id) for i in items]
    if len({p.store_id for p in products})!=1:raise HTTPException(400,'Pilot supports one store per order')
    for i,p in zip(items,products):
        if p.stock<i.quantity:raise HTTPException(409,f'Insufficient stock: {p.id}')
    order=Order(id=new_id('ord'),user_id=user.id,store_id=products[0].store_id,status='AWAITING_PAYMENT',merchandise_cents=sum(i.quantity*p.price_cents for i,p in zip(items,products)),delivery_cents=20000,recipient_address=body.recipientAddress,created_at=now(),idempotency_key=idempotency_key)
    db.add(order)
    for i,p in zip(items,products):
        p.stock-=i.quantity;db.add(OrderLine(id=new_id('line'),order_id=order.id,product_id=p.id,quantity=i.quantity,price_cents=p.price_cents));db.delete(i)
    audit(db,order.id,'INVENTORY_RESERVED');db.commit();return order_view(order)
@app.get('/v1/orders')
def list_orders(user:User=Depends(current_user),db:Session=Depends(db_session)):
    q=db.query(Order) if user.role=='ADMIN' else db.query(Order).filter_by(user_id=user.id)
    return [order_view(o) for o in q.all()]
@app.get('/v1/orders/{orderId}')
def get_order(orderId:str,user:User=Depends(current_user),db:Session=Depends(db_session)):
    o=db.get(Order,orderId)
    if not o:raise HTTPException(404,'Order not found')
    if user.role not in ('ADMIN','STORE_USER') and o.user_id!=user.id:raise HTTPException(403,'Not your order')
    return order_view(o)
@app.post('/v1/orders/{orderId}/cancel')
def cancel_order(orderId:str,user:User=Depends(require('CUSTOMER')),db:Session=Depends(db_session)):
    o=db.get(Order,orderId)
    if not o or o.user_id!=user.id:raise HTTPException(404,'Order not found')
    if o.status!='AWAITING_PAYMENT':raise HTTPException(409,'Cancellation after payment requires refund workflow')
    for line in db.query(OrderLine).filter_by(order_id=o.id):db.get(Product,line.product_id).stock+=line.quantity
    o.status='CANCELLED';audit(db,o.id,'ORDER_CANCELLED','Inventory released');db.commit();return order_view(o)
@app.post('/v1/payments/mpesa/stk-push',status_code=202)
def stk(body:Pay,user:User=Depends(require('CUSTOMER')),db:Session=Depends(db_session)):
    o=db.get(Order,body.orderId)
    if not o or o.user_id!=user.id:raise HTTPException(404,'Order not found')
    if o.status!='AWAITING_PAYMENT':raise HTTPException(409,'Order is not payable')
    p=db.query(Payment).filter_by(order_id=o.id).first()
    if not p:p=Payment(id=new_id('pay'),order_id=o.id,status='PENDING',amount_cents=o.merchandise_cents+o.delivery_cents,provider='SIMULATED_MPESA');db.add(p)
    db.commit();return {'paymentId':p.id,'status':p.status,'mode':'SIMULATED','message':'No real STK push was sent'}
@app.get('/v1/payments/{paymentId}')
def payment_status(paymentId:str,user:User=Depends(current_user),db:Session=Depends(db_session)):
    p=db.get(Payment,paymentId)
    if not p:raise HTTPException(404,'Payment not found')
    o=db.get(Order,p.order_id)
    if o.user_id!=user.id and user.role!='ADMIN':raise HTTPException(403,'Not your payment')
    return {'paymentId':p.id,'status':p.status,'amountKES':money(p.amount_cents)}
@app.post('/v1/simulator/payments/{paymentId}/confirm')
def simulate_confirm(paymentId:str,user:User=Depends(require('ADMIN')),db:Session=Depends(db_session)):
    if os.getenv('ENVIRONMENT')=='production':raise HTTPException(404,'Unavailable')
    p=db.get(Payment,paymentId)
    if not p:raise HTTPException(404,'Payment not found')
    o=db.get(Order,p.order_id)
    if p.status=='SUCCESS':return {'status':'SUCCESS','orderStatus':o.status}
    if o.status!='AWAITING_PAYMENT':raise HTTPException(409,'Order not payable')
    p.status='SUCCESS';o.status='PAID';db.add(Delivery(id=new_id('del'),order_id=o.id,status='PENDING'));audit(db,o.id,'PAYMENT_CONFIRMED','SIMULATED');db.commit();return {'status':'SUCCESS','orderStatus':o.status}
@app.post('/v1/admin/orders/{orderId}/fulfilment')
def fulfil(orderId:str,body:UpdateStatus,user:User=Depends(require('ADMIN','STORE_USER')),db:Session=Depends(db_session)):
    o=db.get(Order,orderId)
    if not o:raise HTTPException(404,'Order not found')
    transitions={'PAID':'PICKING','PICKING':'PACKED'}
    if transitions.get(o.status)!=body.status:raise HTTPException(409,'Invalid fulfilment transition')
    o.status=body.status;audit(db,o.id,'FULFILMENT_'+body.status);db.commit();return order_view(o)
@app.post('/v1/dispatch/jobs/{orderId}/assign')
def assign(orderId:str,body:Assign,user:User=Depends(require('ADMIN')),db:Session=Depends(db_session)):
    o=db.get(Order,orderId);d=db.query(Delivery).filter_by(order_id=orderId).first()
    if not o or not d:raise HTTPException(404,'Delivery not found')
    if o.status!='PACKED' or d.rider_id:raise HTTPException(409,'Order not ready or rider already assigned')
    d.rider_id=body.riderId;d.status='ASSIGNED';o.status='DISPATCHED';otp=f'{secrets.randbelow(1000000):06d}';d.otp_hash=hashlib.sha256(otp.encode()).hexdigest();audit(db,o.id,'RIDER_ASSIGNED',body.riderId);db.commit()
    # Demo-only OTP: real service must deliver OTP to recipient over verified notification channel.
    return {'deliveryId':d.id,'status':d.status,'demoOtp':otp}
@app.get('/v1/orders/{orderId}/delivery')
def delivery_status(orderId:str,user:User=Depends(current_user),db:Session=Depends(db_session)):
    o=db.get(Order,orderId)
    if not o:raise HTTPException(404,'Order not found')
    if o.user_id!=user.id and user.role not in ('ADMIN','DRIVER'):raise HTTPException(403,'Not authorised')
    d=db.query(Delivery).filter_by(order_id=orderId).first()
    return {'status':d.status,'riderId':d.rider_id} if d else {'status':'NOT_DISPATCHED'}
@app.post('/v1/delivery/jobs/{deliveryId}/proof')
def delivery_proof(deliveryId:str,body:Proof,user:User=Depends(require('ADMIN','DRIVER')),db:Session=Depends(db_session)):
    d=db.get(Delivery,deliveryId)
    if not d:raise HTTPException(404,'Delivery not found')
    if user.role=='DRIVER' and d.rider_id!=user.id:raise HTTPException(403,'Not assigned to you')
    if d.status!='ASSIGNED':raise HTTPException(409,'Delivery not assigned')
    if not hmac.compare_digest(d.otp_hash,hashlib.sha256(body.otp.encode()).hexdigest()):raise HTTPException(403,'Invalid delivery OTP')
    d.status='DELIVERED';o=db.get(Order,d.order_id);o.status='DELIVERED';audit(db,o.id,'DELIVERED');db.commit();return {'status':'DELIVERED'}
@app.post('/v1/admin/stores/{storeId}/inventory')
def update_inventory(storeId:str,body:StockUpdate,user:User=Depends(require('ADMIN')),db:Session=Depends(db_session)):
    p=db.get(Product,body.productId)
    if not p or p.store_id!=storeId:raise HTTPException(404,'Product not found at store')
    p.stock=body.stock;db.commit();return {'productId':p.id,'stock':p.stock}
@app.get('/v1/control-room/orders')
def control_orders(user:User=Depends(require('ADMIN')),db:Session=Depends(db_session)):
    return [{'order':order_view(o),'events':[{'type':e.event_type,'time':e.created_at} for e in db.query(Event).filter_by(order_id=o.id).all()]} for o in db.query(Order).all()]

def seed():
    with SessionLocal() as db:
        if db.get(Store,'store-rongai-1'):return
        db.add(Store(id='store-rongai-1',name='Rongai Demo Supermarket',location='Ongata Rongai'))
        db.add_all([Product(id='prod-milk',store_id='store-rongai-1',name='Milk 500ml',price_cents=6500,stock=100),Product(id='prod-bread',store_id='store-rongai-1',name='Bread 400g',price_cents=7000,stock=100)])
        # Credentials for demo only; change for any shared environment.
        salt=secrets.token_hex(16);db.add(User(id='demo-admin',name='Demo Admin',phone='+254700000001',salt=salt,password_hash=hash_password('DemoAdmin123!',salt),role='ADMIN'))
        db.commit()
seed()
