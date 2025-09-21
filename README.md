**JWKS Server (Flask)**
JWKS server that generates RSA keypairs with unique kid and expiration time stamps, serves a JWKS
containing only unexpired public keys, and issues JWTS from POST /auth

API Endpoints:
GET /.well-knwon/jwks.json   returns a JWKS containing only the active public key.
POST /auth    returns valid JWT with header that includes kid matching the active key in JWKS
POST /auth?expired=1   returns an expired JWT

**BEFORE RUNNING**
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

**TO Run THE SERVER**
python app.py

ON SECOND TERMINAL: for tests

ruff check .
python blackbox_client.py
pytest -q --maxfail=1 --disable-warnings --cov=app --cov=keys --cov-report=term-missing


