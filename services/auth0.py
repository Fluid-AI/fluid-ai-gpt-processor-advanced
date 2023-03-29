from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from six.moves.urllib.request import urlopen
from jose import jwt
import json
import os

ALGORITHMS = ["RS256"]
AUTH0_DOMAIN = os.environ['AUTH0_DOMAIN']
API_AUDIENCE = os.environ['AUTH0_API_AUDIENCE']

async def authorization_middleware(request: Request, call_next):
    try :
        # Validating if authorization header is provided or not
        auth_token = get_token_auth_header(request)
        if(auth_token['token'] is None):
            return JSONResponse(auth_token, 401)

        # Validating token
        token_payload = get_token_payload(auth_token['token'])
        if(token_payload['payload'] is None):
            return JSONResponse(token_payload, 401)

        # If everything works fine then moving to next route handler
        response = await call_next(request)
        return response
    except Exception as e:
        print("Error: ", e)
        raise HTTPException(status_code=500)

def get_token_auth_header(request: Request):
    try :
        """Obtains the Access Token from the Authorization Header
        """
        auth = request.headers.get("Authorization")
        if not auth:
            return { "token": None, "code": "authorization_header_missing", "description": "Authorization header is expected" }

        parts = auth.split()

        if parts[0].lower() != "bearer":
            return { "token": None, "code": "invalid_header", "description": "Authorization header must start with Bearer" }
        elif len(parts) == 1:
            return { "token": None, "code": "invalid_header", "description": "Token not found" }
        elif len(parts) > 2:
            return { "token": None, "code": "invalid_header", "description": "Authorization header must be Bearer token" }

        token = parts[1]
        return { "token": token }
    except Exception as e:
        print("Error: ", e)
        raise HTTPException(status_code=500)

def get_token_payload(token):
    try:
        jsonurl = urlopen("https://"+AUTH0_DOMAIN+"/.well-known/jwks.json")
        jwks = json.loads(jsonurl.read())
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if rsa_key:
            payload = None
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=API_AUDIENCE,
                    issuer="https://"+AUTH0_DOMAIN+"/"
                )
            except jwt.ExpiredSignatureError:
                return { "payload": None, "code": "token_expired", "description": "token is expired" }
            except jwt.JWTClaimsError:
                return { "payload": None, "code": "invalid_claims", "description": "incorrect claims, please check the audience and issuer" }
            except Exception:
                return { "payload": None, "code": "invalid_header", "description": "Unable to parse authentication token." }
            return { "payload": payload }
    except Exception as e:
        print("Error: ", e)
        raise HTTPException(status_code=500)