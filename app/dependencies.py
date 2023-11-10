from datetime import datetime, timedelta
from datetime import datetime, timedelta
from typing import Annotated
from fastapi import Depends, HTTPException, status
from jose import JWTError, jwt
from pydantic import  ValidationError
from pymongo.collection import Collection
from bson.objectid import ObjectId

from .utils import pwd_context, oauth2_scheme
from .schemas import TokenData, Auth, UserInDB
from .constants import SECRET_KEY, ALGORITHM, PASSWORD_SALT
from .db import auth_db, permissions_db

def get_password_hash(password):
    return pwd_context.hash(password, salt=PASSWORD_SALT)
def verify_password(plain_password, hashed_password):
    # print("passed password: " + plain_password, "hashed:"+get_password_hash(plain_password), "actual:"+hashed_password,sep="\n")
    # print(f"{pwd_context.verify(plain_password, hashed_password)=}")
    return pwd_context.verify(plain_password, hashed_password)





def get_user_auth_by_username(db: Collection, username: str)-> Auth | None:
    # search for auth by username
    result = db.find_one({"username": username})
    if result:
        # print(result)
        auth_dict = Auth(id=str(result["_id"]), hashed_password=result["hashed_password"], role=result["role"], user_id=result["user_id"])
        return auth_dict

def get_user_auth_by_id(db: Collection, id: str)-> Auth | None:
    """Search for auth by id"""
    result = db.find_one({"_id": ObjectId(id)})
    if result:
        auth_dict = Auth(id=str(result["_id"]), hashed_password=result["hashed_password"], role=result["role"], user_id=result["user_id"])
        return auth_dict


def authenticate_user(auth_db, username: str, password: str):
    user_auth = get_user_auth_by_username(auth_db, username)
    if not user_auth:
        return False
    # print("got this auth reg ", user_auth)
    if not verify_password(password, user_auth.hashed_password):
        return False
    return user_auth


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)]
) -> Auth:
    authenticate_value = "Bearer"
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": authenticate_value},
    )
    print("got this token ",token)
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print("got this payload ",payload)
        user_id: str | None= payload.get("user_id", None)
        print("got this user_id ",user_id)
        id: str | None = payload.get("id", None)
        print("got this id ",id)
        if user_id is None or id is None:
            raise credentials_exception
        token_scopes = payload.get("scopes", [])
        token_data = TokenData(user_id=user_id, id=id, scopes=token_scopes)
    except (JWTError, ValidationError) as e:
        raise credentials_exception

    user_auth = get_user_auth_by_id(auth_db,token_data.id)

    if user_auth is None:
        raise credentials_exception
    
    if user_auth.role.value not in token_data.scopes:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not enough permissions",
            headers={"WWW-Authenticate": authenticate_value},
        )
    return user_auth

async def validate_role(
        permissions_db,
        user_auth: Auth,
        url_path: str,
        method: str
):
    result = permissions_db.find_one({"url": url_path}, {"_id": 0})
    if result:
        if user_auth.role.value in result:
            if method in result[user_auth.role.value]:
                return True
    return False


# A function to register a new user
async def register_user(
    auth_db: Collection,
    username: str,
    password: str,
    user_id: str,
    role: str
):
  _result = auth_db.insert_one(
      {
          "user_id": user_id,
          "username": username,
          "hashed_password": get_password_hash(password),
          "role": role,
      }
  )
  return True



