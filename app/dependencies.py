from datetime import datetime, timedelta
from datetime import datetime, timedelta
from typing import Annotated
from fastapi import Depends, HTTPException, status
from jose import JWTError, jwt
from pydantic import  ValidationError

from .utils import pwd_context, oauth2_scheme
from .schemas import TokenData, Auth, UserInDB
from .constants import SECRET_KEY, ALGORITHM
from .db import auth_db, permissions_db

def get_password_hash(password):
    return pwd_context.hash(password)
def verify_password(plain_password, hashed_password):
    print("passed password: " + plain_password, "hashed:"+get_password_hash(plain_password), "actual:"+hashed_password,sep="\n")
    return pwd_context.verify(plain_password, hashed_password)




def get_user(db, username: str)-> UserInDB | None:
    # search for user in db
    # search by username
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def get_user_auth(db, user_id: str)-> Auth | None:
    # search for auth by user id
    result = db.find_one({"user_id": user_id}, {"_id": 0})
    if result:
        auth_dict = Auth(**result)
        return auth_dict


def authenticate_user(client_db, auth_db, username: str, password: str):
    user = get_user(client_db, username)
    print("user from db: ",user)
    if not user:
        return False
    user_auth = get_user_auth(auth_db, user.id)
    print("user_auth from db: ",user_auth)
    if not user_auth:
        return False
    if not verify_password(password, user_auth.hashed_password):
        return False
    return user, user_auth


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
):
    authenticate_value = "Bearer"
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": authenticate_value},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        token_scopes = payload.get("scopes", [])
        token_data = TokenData(scopes=token_scopes, username=user_id)
    except (JWTError, ValidationError) as e:
        print(e)
        raise credentials_exception
    user_auth = get_user_auth(auth_db, user_id=token_data.username)
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

