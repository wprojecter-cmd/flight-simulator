import os, time, secrets, hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional
import bcrypt, httpx, jwt
from bson import ObjectId
from fastapi import FastAPI, HTTPException, Header, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING

ROOT=os.path.dirname(os.path.abspath(__file__))
URI=os.getenv('MONGODB_URI',''); DBNAME=os.getenv('MONGODB_DB','flight_simulator')
SECRET=os.getenv('SESSION_SECRET',''); WEATHER_KEY=os.getenv('OPENWEATHER_API_KEY','')
app=FastAPI(title='Flight Simulator Online',version='0.1.0')
app.mount('/static',StaticFiles(directory=os.path.join(ROOT,'static')),name='static')
client=None; db=None; sockets=set(); live={}
def now(): return datetime.now(timezone.utc)
def need_db():
    if db is None: raise HTTPException(503,'MongoDB is not configured. Set MONGODB_URI in Render environment variables.')
def new_token(uid):
    if not SECRET: raise HTTPException(503,'SESSION_SECRET is not configured.')
    exp=now()+timedelta(days=30)
    token=jwt.encode({'sub':uid,'iat':int(time.time()),'exp':int(exp.timestamp()),'jti':secrets.token_urlsafe(12)},SECRET,algorithm='HS256')
    return token,exp
@app.on_event('startup')
async def startup():
    global client,db
    if URI:
        client=AsyncIOMotorClient(URI,serverSelectionTimeoutMS=7000); db=client[DBNAME]
        try:
            await client.admin.command('ping')
            await db.users.create_index([('email_lower',ASCENDING)],unique=True)
            await db.users.create_index([('username_lower',ASCENDING)],unique=True)
            await db.sessions.create_index('expires_at',expireAfterSeconds=0)
            await db.profiles.create_index('user_id',unique=True)
        except Exception as e: print('MongoDB connection/index error:',e)
@app.on_event('shutdown')
async def shutdown():
    if client: client.close()
@app.get('/')
async def home(): return FileResponse(os.path.join(ROOT,'static','index.html'))
@app.get('/api/health')
async def health():
    state='not_configured'
    if client:
        try: await client.admin.command('ping'); state='connected'
        except Exception: state='unavailable'
    return {'status':'ok','database':state}
class Auth(BaseModel):
    email: EmailStr
    password: str=Field(min_length=8,max_length=128)
    username: Optional[str]=Field(default=None,min_length=3,max_length=24)
class AircraftChoice(BaseModel): aircraft_id: str
class Position(BaseModel):
    lat: float=Field(ge=-90,le=90); lon: float=Field(ge=-180,le=180)
    altitude: float=Field(default=1000,ge=0,le=60000); heading: float=Field(default=0,ge=0,le=360)
    aircraft_id: str='airbus-a320'
async def get_user(auth):
    need_db()
    if not auth or not auth.lower().startswith('bearer '): raise HTTPException(401,'Please sign in.')
    token=auth.split(' ',1)[1].strip()
    try: payload=jwt.decode(token,SECRET,algorithms=['HS256']); uid=payload['sub']
    except Exception: raise HTTPException(401,'Session expired. Please sign in again.')
    session=await db.sessions.find_one({'token_hash':hashlib.sha256(token.encode()).hexdigest(),'user_id':uid,'expires_at':{'$gt':now()}})
    if not session: raise HTTPException(401,'Session is no longer active. Please sign in again.')
    user=await db.users.find_one({'_id':ObjectId(uid)},{'password_hash':0})
    if not user: raise HTTPException(401,'Account not found.')
    return user,token
async def make_session(uid):
    token,exp=new_token(uid)
    await db.sessions.insert_one({'user_id':uid,'token_hash':hashlib.sha256(token.encode()).hexdigest(),'created_at':now(),'expires_at':exp})
    return token,exp
@app.post('/api/auth/register')
async def register(data:Auth):
    need_db(); email=str(data.email).lower().strip(); username=(data.username or email.split('@')[0]).strip()
    if len(username)<3: raise HTTPException(400,'Username must have at least 3 characters.')
    if await db.users.find_one({'$or':[{'email_lower':email},{'username_lower':username.lower()}]}): raise HTTPException(409,'Email or username already exists.')
    result=await db.users.insert_one({'email':email,'email_lower':email,'username':username,'username_lower':username.lower(),'password_hash':bcrypt.hashpw(data.password.encode(),bcrypt.gensalt()).decode(),'created_at':now()})
    uid=str(result.inserted_id)
    await db.profiles.insert_one({'user_id':uid,'selected_aircraft':'airbus-a320','last_route':None,'updated_at':now()})
    token,exp=await make_session(uid)
    return {'token':token,'expires_at':exp.isoformat(),'user':{'id':uid,'email':email,'username':username},'profile':{'selected_aircraft':'airbus-a320'}}
@app.post('/api/auth/login')
async def login(data:Auth):
    need_db(); email=str(data.email).lower().strip(); u=await db.users.find_one({'email_lower':email})
    if not u or not bcrypt.checkpw(data.password.encode(),u['password_hash'].encode()): raise HTTPException(401,'Email or password is incorrect.')
    token,exp=await make_session(str(u['_id'])); p=await db.profiles.find_one({'user_id':str(u['_id'])}) or {}
    return {'token':token,'expires_at':exp.isoformat(),'user':{'id':str(u['_id']),'email':u['email'],'username':u['username']},'profile':{'selected_aircraft':p.get('selected_aircraft','airbus-a320')}}
@app.get('/api/auth/me')
async def me(authorization:Optional[str]=Header(default=None)):
    u,_=await get_user(authorization); p=await db.profiles.find_one({'user_id':str(u['_id'])}) or {}
    return {'user':{'id':str(u['_id']),'email':u['email'],'username':u['username']},'profile':{'selected_aircraft':p.get('selected_aircraft','airbus-a320'),'last_route':p.get('last_route')}}
@app.post('/api/auth/logout')
async def logout(authorization:Optional[str]=Header(default=None)):
    u,t=await get_user(authorization); await db.sessions.delete_one({'user_id':str(u['_id']),'token_hash':hashlib.sha256(t.encode()).hexdigest()}); return {'ok':True}
@app.put('/api/profile/aircraft')
async def aircraft(data:AircraftChoice,authorization:Optional[str]=Header(default=None)):
    u,_=await get_user(authorization)
    if data.aircraft_id not in {'airbus-a320','cessna-172','business-jet'}: raise HTTPException(400,'Unknown aircraft.')
    await db.profiles.update_one({'user_id':str(u['_id'])},{'$set':{'selected_aircraft':data.aircraft_id,'updated_at':now()}},upsert=True)
    return {'ok':True,'selected_aircraft':data.aircraft_id}
async def broadcast():
    stale=[]; msg={'type':'players','players':list(live.values())}
    for ws in list(sockets):
        try: await ws.send_json(msg)
        except Exception: stale.append(ws)
    for ws in stale: sockets.discard(ws)
@app.post('/api/flight/position')
async def position(data:Position,authorization:Optional[str]=Header(default=None)):
    u,_=await get_user(authorization); uid=str(u['_id']); doc={'user_id':uid,'username':u['username'],**data.model_dump(),'updated_at':now()}
    await db.flight_positions.update_one({'user_id':uid},{'$set':doc},upsert=True); live[uid]={**doc,'updated_at':doc['updated_at'].isoformat()}; await broadcast(); return {'ok':True}
@app.get('/api/flight/players')
async def players(authorization:Optional[str]=Header(default=None)):
    await get_user(authorization); cur=db.flight_positions.find({'updated_at':{'$gt':now()-timedelta(seconds=30)}},{'_id':0}); out=[]
    async for p in cur:
        if p.get('updated_at'): p['updated_at']=p['updated_at'].isoformat()
        out.append(p)
    return {'players':out}
@app.get('/api/weather')
async def weather(lat:float,lon:float,authorization:Optional[str]=Header(default=None)):
    await get_user(authorization)
    if not WEATHER_KEY: raise HTTPException(503,'Set OPENWEATHER_API_KEY in Render environment variables.')
    async with httpx.AsyncClient(timeout=8) as c: r=await c.get('https://api.openweathermap.org/data/2.5/weather',params={'lat':lat,'lon':lon,'appid':WEATHER_KEY,'units':'metric'})
    if r.status_code!=200: raise HTTPException(502,'Weather provider request failed.')
    d=r.json(); return {'temperature_c':d.get('main',{}).get('temp'),'wind_speed_ms':d.get('wind',{}).get('speed'),'humidity':d.get('main',{}).get('humidity'),'description':(d.get('weather') or [{}])[0].get('description'),'clouds_percent':d.get('clouds',{}).get('all'),'visibility_m':d.get('visibility')}
@app.websocket('/ws/flight')
async def ws_flight(ws:WebSocket):
    await ws.accept(); sockets.add(ws)
    try:
        await ws.send_json({'type':'players','players':list(live.values())})
        while True: await ws.receive_text()
    except (WebSocketDisconnect,Exception): sockets.discard(ws)
