from dotenv import dotenv_values


config_token = dotenv_values('.env')

SECRET_KEY = config_token["SECRET_KEY"]
ALGORITHM = config_token["ALGORITHM"]
ACCESS_TOKEN_EXPIRE_MINUTES = int(config_token["ACCESS_TOKEN_EXPIRE_MINUTES"])
