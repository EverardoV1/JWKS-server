import requests

#url where flask is listening
BASE = "http://localhost:8080"

#fetch jwks
print("GET JWKS:")
#send http get request and turn response into python dictionary
print(requests.get(f"{BASE}/.well-known/jwks.json").json())

#ask server for a valid JWT
print("\nPOST /auth (valid):")
tok_valid = requests.post(f"{BASE}/auth").json() #post to /auth with no body
print(tok_valid)

#Ask server for an expired JWT
print("\nPOST /auth?expired=1 (expired):")
tok_exp = requests.post(f"{BASE}/auth?expired=1").json()
print(tok_exp)