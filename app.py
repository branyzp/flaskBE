import os
import psycopg2
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
from flask_cors import CORS, cross_origin
from flask_jwt_extended import create_access_token, get_jwt, get_jwt_identity, unset_jwt_cookies, jwt_required, JWTManager

# user table
DROP_USER_TABLE = (
    "DROP TABLE IF EXISTS users"
)
CREATE_USER_TABLE = (
    "CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username TEXT UNIQUE, password TEXT, firstname TEXT, lastname TEXT);"
)

INSERT_USER = (
    "INSERT INTO users (username, password, firstname, lastname) VALUES (%s,%s,%s,%s)"
)

VIEW_USER = (
    "SELECT * FROM users"
)

LOGIN_USER_CHECK_USERNAME = (
    "SELECT * FROM users WHERE username = '{username}'"
)
UPDATE_USER = (
    "UPDATE users SET (username, password, firstname, lastname) VALUES (%s,%s,%s,%s) WHERE id = (%s)"
)


# expenses table
DROP_EXPENSES_TABLE = (
    "DROP TABLE IF EXISTS expenses"
)
CREATE_EXPENSES_TABLE = (
    "CREATE TABLE IF NOT EXISTS expenses(id SERIAL PRIMARY KEY, userid INTEGER FOREIGN KEY REFERENCES users(id), expense TEXT , category TEXT)"
)

INSERT_EXPENSE = (
    "INSERT INTO expenses (userid, expense, category) VALUES (%s,%s,%s)"
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


@ app.route('/')
def index():
    return "Hello World"


@ app.get('/api/viewusers')
def view_users():
    with connection:
        conn = connection.cursor()
        conn.execute(VIEW_USER)
        res = conn.fetchall()
    return res


@ app.post('/api/seeduser')
def seed_user():
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


@ app.post('/api/register')
@ cross_origin()
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


@ app.post('/api/login')
@ cross_origin()
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
                    response = {"access_token": access_token,
                                "user_details": user}
                    return response

    return {"message": f"trying to login with {username} and {password} failed"}


# @ app.put('/api/updateuser')
# @ cross_origin()
# def update_user():
#     data = request.get_json()
#     username = data["username"]
#     password = data["password"]
#     firstname = data["firstname"]
#     lastname = data["lastname"]
#     id = int(data["id"])
#     hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
#     with connection:
#         with connection.cursor() as cursor:
#             cursor.execute(
#                 UPDATE_USER, (username, hashed_password, firstname, lastname, id))
#     return {"message": f"userid {id} details updated to username:{username}, password:{password}, firstname:{firstname}, lastname:{lastname}"}, 201

# @app.post('/api/seedexpenses')
# @cross_origin()
# def seed_expense():

#     with connection:
#         with connection.cursor() as cursor:
#             cursor.execute(DROP_EXPENSES_TABLE)
#             cursor.execute(CREATE_EXPENSES_TABLE)
#             cursor.execute(INSERT_EXPENSE)

@ app.put('/api/updateuser')
@ cross_origin()
def update_user():
    data = request.get_json()
    username = data["username"]
    password = data["password"]
    firstname = data["firstname"]
    lastname = data["lastname"]
    id = int(data["id"])
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT username FROM users WHERE id={id}")
            OldUsername = cursor.fetchone()

            if OldUsername != username:
                cursor.execute(
                    f"UPDATE users SET firstname='{firstname}',lastname='{lastname}',username='{username}',password='{hashed_password}' WHERE id={id}")
            else:
                cursor.execute(
                    f"UPDATE users SET firstname='{firstname}',lastname='{lastname}',password='{hashed_password}' WHERE id={id}")

    return {"message": f"userid {id} details updated to username:{username}, password:{password}, firstname:{firstname}, lastname:{lastname}"}, 201


if __name__ == "__main__":
    app.run(debug=True, port=8000)
