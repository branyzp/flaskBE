import os
import psycopg2
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
from flask_cors import CORS, cross_origin
from flask_jwt_extended import create_access_token, get_jwt, get_jwt_identity, unset_jwt_cookies, jwt_required, JWTManager


DROP_USER_TABLE = (

    "DROP TABLE IF EXISTS users"
)
CREATE_USER_TABLE = (
    "CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username TEXT UNIQUE, password TEXT, firstname TEXT, lastname TEXT);"
)

INSERT_USER = (
    "INSERT INTO users (username, password, firstname, lastname) VALUES (%s,%s,%s,%s)"
)

LOGIN_USER_CHECK_USERNAME = (
    "SELECT * FROM users WHERE username = '{username}'"
)


load_dotenv()

app = Flask(__name__)
bcrypt = Bcrypt(app)
url = os.getenv("DATABASE_URL")
connection = psycopg2.connect(url)
CORS(app)

# JWT
app.config["JWT_SECRET_KEY"] = "jwtsecretkey"
jwt = JWTManager(app)


@app.route('/')
def index():
    return "Hello World"


@app.post('/api/seed')
def seed():
    username = "branyzp@gmail.com"
    password = "password123"
    firstname = "Brandon"
    lastname = "Yeo"
    hashed_password = bcrypt.generate_password_hash(password)
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(DROP_USER_TABLE)
            cursor.execute(CREATE_USER_TABLE)
            cursor.execute(
                INSERT_USER, (username, hashed_password, firstname, lastname,))
    return {"message": "user table seeded"}, 201


@app.post('/api/register')
@cross_origin()
def create_user():
    data = request.get_json()
    username = data["username"]
    password = data["password"]
    firstname = data["firstname"]
    lastname = data["lastname"]
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(CREATE_USER_TABLE)
            cursor.execute(
                INSERT_USER, (username, hashed_password, firstname, lastname,))
    return {"message": f"user with username:{username} created."}, 201


@app.post('/api/login')
@cross_origin()
def login():
    data = request.get_json()
    username = data["username"]
    password = data["password"]
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT * FROM users WHERE username = '{username}'")
            user = cursor.fetchone()
            if user:
                if bcrypt.check_password_hash(user[2], password):
                    access_token = create_access_token(identity=username)
                    response = {"access_token": access_token}
                    return response

    return {"message": f"trying to login with {username} and {password}. found {user[2]}"}


if __name__ == "__main__":
    app.run(debug=True, port=8000)
