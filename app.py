from flask import Flask, jsonify, request
import jwt

from keys import time_now, create_jwk, ACTIVE_KEY, EXPIRED_KEY


app = Flask(__name__)

#JWKS endpoint
@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():

    keys = []

    #if the active key is valid still, add the public portion to JWKS
    if ACTIVE_KEY["expires_at"] > time_now():
        keys.append(create_jwk(ACTIVE_KEY["public"], ACTIVE_KEY["kid"]))

    #return JWKS
    return jsonify({"keys": keys}) 


#Authentication endpoint
@app.route("/auth", methods=["POST"])
def auth():

    #if the string contains "expired" return expired token
    use_expired = "expired" in request.args

    if use_expired:
        key_info = EXPIRED_KEY
        expired_time = time_now() - 900

    #if not expired use active key to create active token, set expir to future
    else:
        key_info = ACTIVE_KEY
        expired_time = time_now() + 900

    #JWT header
    headers = {"kid": key_info["kid"]}

    #JWT payload
    payload = {
        "sub": "test_user",
        "iat": time_now(),
        "exp": expired_time
    }

    #create the RS256 signed JWT using the selected private key
    token = jwt.encode(payload, key_info["private"], algorithm="RS256", headers=headers)

    #return JSON w the token string
    return jsonify({"token": token})



if __name__ == "__main__":
    app.run(host="0.0.0.0", port= 8080, debug=True)

