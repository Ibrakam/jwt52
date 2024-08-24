from datetime import timedelta, datetime

import jwt
from fastapi.security import OAuth2PasswordBearer
from typing import Optional
from models import User
from config import ALGORITHM, SECRET_KEY

oauth_schema = OAuth2PasswordBearer(tokenUrl='token')


def verify_password(password, hashed_password):
    return password == hashed_password


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return User(**user_dict)


def create_access_token(data: dict, expires_date: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_date:
        expire = datetime.utcnow() + expires_date
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

