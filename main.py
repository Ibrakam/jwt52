import jwt
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from models import Token, TokenData, User
from hash import get_user, verify_password, create_access_token
from datetime import timedelta, datetime
from config import ACCESS_TOKEN_EXPIRE_MINUTES, SECRET_KEY, ALGORITHM

app = FastAPI(docs_url="/")


def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


fake_db = {
    "admin": {
        "username": "admin",
        "password": "admin"
    }
}


@app.post("/token", response_model=Token)
async def login_for_access_token(form: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_db, form.username, form.password)
    if not user:
        return HTTPException(
            status_code=404,
            detail="Неправильный username или пароль"
        )
    access_token_expire = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username},
                                       expires_date=access_token_expire)
    return {"access_token": access_token, "token_type": "bearer"}


from hash import oauth_schema


async def get_current_user(token: str = Depends(oauth_schema)):
    exceptions = HTTPException(
        status_code=404,
        detail="Неправильный токен"
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise exceptions
        token_data = TokenData(username=username)
    except jwt.PyJWTError:
        raise exceptions
    user = get_user(fake_db, token_data.username)
    if user is None:
        raise exceptions
    return user


@app.get('/user/me', response_model=User)
async def get_user_me(user: User = Depends(get_current_user)):
    return user
