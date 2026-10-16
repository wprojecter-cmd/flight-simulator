# Flight Simulator Online

Render-ready browser flight simulator starter using FastAPI, MongoDB, Three.js, a 3D globe and WebSockets.

## Deploy to Render
1. Upload these files to `wprojecter-cmd/flight-simulator` on GitHub.
2. Create a Render **Web Service** from that repository.
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Set environment variables in Render: `MONGODB_URI`, `MONGODB_DB=flight_simulator`, `SESSION_SECRET` (long random secret), and `OPENWEATHER_API_KEY`.

## Included
- Full-screen registration and login; MongoDB accounts and signed 30-day bearer sessions.
- Saved aircraft choice (Airbus A320 S7 GLB from the supplied Pinnogram repository, Cessna 172 and business jet procedural models).
- Four game menu cards, Three.js hangar, 3D Earth globe, place/coordinate route planner, starter flight scene, weather endpoint and live pilot-position API/WebSocket.

## Account persistence
MongoDB stores account data; the browser stores the signed session token. A redeploy or different route on the same origin does not reset the account. A different domain/browser/device cannot safely recognize the user without the existing token or a login step. Never store secrets in source code.

## Fidelity note
This is the foundation version, not yet Microsoft Flight Simulator-level rendering. Real continuously streamed photogrammetry/elevation tiles, accurate aircraft physics, real-time sun/night calculations, volumetric weather/clouds and synchronized multiplayer aircraft need further development and a suitable terrain/imagery provider.
