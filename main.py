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
SECRET=os.getenv('SESSION_SECRET',''); WEATHER_KEY=os.getenv('OPENWEATHER_API_KEY',''); CESIUM_ION_MANAGEMENT_TOKEN=os.getenv('CESIUM_ION_MANAGEMENT_TOKEN','').strip()
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
@app.get('/api/atc/cesium-token')
async def atc_cesium_token():
    return {'token': os.getenv('CESIUM_ION_TOKEN', '').strip()}
@app.get('/atc')
async def atc_page(): return FileResponse(os.path.join(ROOT,'static','atc.html'))
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
    speed: float=Field(default=120,ge=0,le=1500)
    aircraft_id: str='airbus-a320'
    origin_lat: Optional[float]=Field(default=None,ge=-90,le=90)
    origin_lon: Optional[float]=Field(default=None,ge=-180,le=180)
    origin_name: Optional[str]=None
    destination_lat: Optional[float]=Field(default=None,ge=-90,le=90)
    destination_lon: Optional[float]=Field(default=None,ge=-180,le=180)
    destination_name: Optional[str]=None
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
@app.post('/api/cesium/token')
async def create_cesium_token(authorization:Optional[str]=Header(default=None)):
    u,_=await get_user(authorization)
    uid=str(u['_id'])
    profile=await db.profiles.find_one({'user_id':uid}) or {}
    existing=profile.get('cesium_ion_token')
    if existing:
        return {'ok':True,'token':existing,'created':False}
    if not CESIUM_ION_MANAGEMENT_TOKEN:
        raise HTTPException(503,'Cesium token creation is not configured. Add CESIUM_ION_MANAGEMENT_TOKEN to Render environment variables. It must be a private ion token with tokens:write scope.')
    app_url='https://flight-simulator-qmyx.onrender.com'
    token_name=('FlightSim-'+''.join(ch for ch in str(u.get('username','Pilot')) if ch.isalnum() or ch in '-_'))[:48]+'-'+uid[-6:]
    payload={'name':token_name,'scopes':['assets:read'],'assetIds':[1],'allowedUrls':[app_url]}
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            response=await c.post('https://api.cesium.com/v2/tokens',headers={'Authorization':'Bearer '+CESIUM_ION_MANAGEMENT_TOKEN,'Accept':'application/json'},json=payload)
    except httpx.HTTPError:
        raise HTTPException(502,'Could not connect to Cesium ion. Please try again.')
    if response.status_code not in (200,201):
        print('Cesium token creation failed:',response.status_code,response.text[:500])
        if response.status_code in (401,403):
            raise HTTPException(502,'Cesium rejected the management token. Check that it is valid and has tokens:write scope.')
        raise HTTPException(502,'Cesium ion could not create a token. Check the Render logs for the provider response.')
    try:
        result=response.json()
    except ValueError:
        raise HTTPException(502,'Cesium ion returned an unreadable response.')
    issued=result.get('token')
    if not isinstance(issued,str) or not issued:
        print('Cesium token response missing token field:',str(result)[:500])
        raise HTTPException(502,'Cesium ion response did not contain a token. Check Render logs.')
    await db.profiles.update_one({'user_id':uid},{'$set':{'cesium_ion_token':issued,'cesium_ion_token_id':result.get('id'),'cesium_ion_token_created_at':now(),'updated_at':now()}},upsert=True)
    return {'ok':True,'token':issued,'created':True}
@app.put('/api/profile/aircraft')
async def aircraft(data:AircraftChoice,authorization:Optional[str]=Header(default=None)):
    u,_=await get_user(authorization)
    if data.aircraft_id not in {'airbus-a320','cessna-172','business-jet','boeing-747','airbus-a380'}: raise HTTPException(400,'Unknown aircraft.')
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
    u,_=await get_user(authorization); uid=str(u['_id']); stamp=now(); point={'lat':data.lat,'lon':data.lon,'altitude':data.altitude,'heading':data.heading,'speed':data.speed,'at':stamp.isoformat()}
    doc={'user_id':uid,'username':u['username'],**data.model_dump(),'updated_at':stamp}
    await db.flight_positions.update_one({'user_id':uid},{'$set':doc,'$push':{'track':{'$each':[point],'$slice':-1200}}},upsert=True)
    live[uid]={**doc,'track':(live.get(uid,{}).get('track',[])+[point])[-1200:],'updated_at':stamp.isoformat()}; await broadcast(); return {'ok':True}
@app.get('/api/atc/flights')
async def atc_flights(authorization:Optional[str]=Header(default=None)):
    await get_user(authorization)
    cur=db.flight_positions.find({'updated_at':{'$gt':now()-timedelta(seconds=30)}},{'_id':0})
    out=[]
    async for p in cur:
        if p.get('updated_at'): p['updated_at']=p['updated_at'].isoformat()
        out.append(p)
    return {'flights':out,'server_time':now().isoformat()}
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
    if not -90 <= lat <= 90 or not -180 <= lon <= 180: raise HTTPException(400,'Invalid coordinates.')
    params={'latitude':lat,'longitude':lon,'current':'temperature_2m,relative_humidity_2m,apparent_temperature,precipitation,rain,showers,snowfall,weather_code,cloud_cover,wind_speed_10m,wind_direction_10m','hourly':'cloud_cover_low,cloud_cover_mid,cloud_cover_high','forecast_days':1,'timezone':'auto'}
    async with httpx.AsyncClient(timeout=18) as c:
        r=await c.get('https://api.open-meteo.com/v1/forecast',params=params)
        if r.status_code!=200:
            print('Open-Meteo detailed weather request failed:',r.status_code,r.text[:300])
            fallback_params={'latitude':lat,'longitude':lon,'current':'temperature_2m,relative_humidity_2m,apparent_temperature,precipitation,rain,showers,snowfall,weather_code,cloud_cover,wind_speed_10m,wind_direction_10m','hourly':'cloud_cover_low,cloud_cover_mid,cloud_cover_high','forecast_days':1,'timezone':'auto','models':'best_match'}
            r=await c.get('https://api.open-meteo.com/v1/forecast',params=fallback_params)
    if r.status_code!=200:
        print('Open-Meteo weather fallback failed:',r.status_code,r.text[:500])
        raise HTTPException(502,'Weather provider is temporarily unavailable. Please retry in a moment.')
    try: d=r.json()
    except ValueError: raise HTTPException(502,'Weather provider returned invalid data.')
    cur=d.get('current') or {}; hourly=d.get('hourly') or {}; times=hourly.get('time') or []
    idx=0
    if cur.get('time') and times:
        idx=min(range(len(times)),key=lambda i:abs((times[i][:13])-(cur['time'][:13]))) if len(times)>0 else 0
    def at(name):
        values=hourly.get(name) or []
        return values[idx] if idx<len(values) else None
    code=cur.get('weather_code',0)
    descriptions={0:'Clear',1:'Mainly clear',2:'Partly cloudy',3:'Overcast',45:'Fog',48:'Rime fog',51:'Light drizzle',53:'Drizzle',55:'Dense drizzle',61:'Light rain',63:'Rain',65:'Heavy rain',71:'Light snow',73:'Snow',75:'Heavy snow',80:'Rain showers',81:'Rain showers',82:'Heavy rain showers',95:'Thunderstorm',96:'Thunderstorm with hail',99:'Severe thunderstorm'}
    return {'temperature_c':cur.get('temperature_2m'),'apparent_temperature_c':cur.get('apparent_temperature'),'wind_speed_ms':round((cur.get('wind_speed_10m') or 0)/3.6,1),'wind_direction_deg':cur.get('wind_direction_10m'),'humidity':cur.get('relative_humidity_2m'),'description':descriptions.get(code,'Variable conditions'),'weather_code':code,'clouds_percent':cur.get('cloud_cover',0),'cloud_low_percent':at('cloud_cover_low') or 0,'cloud_mid_percent':at('cloud_cover_mid') or 0,'cloud_high_percent':at('cloud_cover_high') or 0,'rain_mm':cur.get('rain',0) or cur.get('showers',0) or 0,'snowfall_cm':cur.get('snowfall',0) or 0,'precipitation_mm':cur.get('precipitation',0) or 0,'time':cur.get('time'),'source':'Open-Meteo'}

@app.websocket('/ws/flight')
async def ws_flight(ws:WebSocket):
    await ws.accept(); sockets.add(ws)
    try:
        await ws.send_json({'type':'players','players':list(live.values())})
        while True: await ws.receive_text()
    except (WebSocketDisconnect,Exception): sockets.discard(ws)
