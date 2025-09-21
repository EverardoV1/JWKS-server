import base64
import time
import uuid

from cryptography.hazmat.primitives.asymmetric import rsa


#return current unix time as an int
def time_now():

    return int (time.time())


#comvert int to base64url without the "=" padding
def base64_url(val):

    #compute min byte length for the int passed
    byte_len = (val.bit_length() + 7) //8

    #convert to big endian
    data = val.to_bytes(byte_len, "big")

    #base64 url encode and remove = on return
    s = base64.urlsafe_b64encode(data).decode("utf-8")
    
    return s.strip("=")


#Build jwk dict from RSA public key and its kid
def create_jwk(public_key, kid):

    #extract RSA numbers
    nums = public_key.public_numbers()
    e = base64_url(nums.e)
    n = base64_url(nums.n)

    return {
        "kty" : "RSA",
        "kid" : kid,
        "use" : "sig",
        "alg" : "RS256",
        "n" : n,
        "e" : e
    }


#Generate 2048 bit RSA private/public key pair
def create_rsa_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    return private_key,public_key


def create_kid():   #create unique key id

    return uuid.uuid4().hex


def init_keys(): 

#active kets expire in 24 hrs
    priv_active, pub_active = create_rsa_pair()
    active = {
        "kid" :create_kid(),
        "private": priv_active,
        "public" :pub_active,
        "expires_at" : time_now() + 24 * 3600
    }

    #create key that expired an hour ago
    priv_expired, pub_expired = create_rsa_pair()
    expired = {
        "kid" : create_kid(),
        "private": priv_expired,
        "public" : pub_expired,
        "expires_at" : time_now() - 3600
    }

    return {"active": active, "expired":expired}

#initializa both keys on import so app can use both directly
keys = init_keys()
ACTIVE_KEY = keys["active"]
EXPIRED_KEY = keys["expired"]

