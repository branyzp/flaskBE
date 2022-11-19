import os
import psycopg2
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
from flask_cors import CORS, cross_origin
from flask_jwt_extended import create_access_token, get_jwt, get_jwt_identity, unset_jwt_cookies, jwt_required, JWTManager
from datetime import datetime
# user table
DROP_USER_TABLE = (
    "DROP TABLE IF EXISTS users CASCADE"
)
CREATE_USER_TABLE = (
    "CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username TEXT UNIQUE, password TEXT, firstname TEXT, lastname TEXT, joinDate TEXT NOT NULL DEFAULT CURRENT_DATE);"
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
    "CREATE TABLE IF NOT EXISTS expenses(id SERIAL PRIMARY KEY, userid INTEGER REFERENCES users(id) ON DELETE CASCADE, category TEXT, expenseName TEXT ,expenseInt INTEGER, expenseDate DATE, expenseComments TEXT)"
)

INSERT_EXPENSE = (
    "INSERT INTO expenses (userid, category, expenseName, expenseInt, expenseDate, expenseComments) VALUES (%s,%s,%s,%s,%s,%s)"
)

VIEW_EXPENSE_SPECIFIC_USER = (
    "SELECT * FROM expenses WHERE userid=(%s)"
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

# USERS API


@ app.get('/api/viewusers')
def view_users():
    with connection:
        conn = connection.cursor()
        conn.execute(VIEW_USER)
        res = conn.fetchall()
    return res


@ app.post('/api/seeduser')
def seed_user():
    data = request.get_json()
    username = data["username"]
    password = data["password"]
    firstname = data["firstname"]
    lastname = data["lastname"]
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
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
                "SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            if user:
                if bcrypt.check_password_hash(user[2], password):
                    access_token = create_access_token(identity=username)
                    response = {"access_token": access_token,
                                "user_details": user}
                    return response

    return {"message": f"trying to login with {username} and {password} failed"}, 500


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


@ app.put('/api/updateuser')
@ cross_origin()
def update_user():
    data = request.get_json()
    username = data["username"]
    # password = data["password"]
    firstname = data["firstname"]
    lastname = data["lastname"]
    id = int(data["id"])
    # hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    with connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT username FROM users WHERE id=%s", (id,))
            OldUsername = cursor.fetchone()

            if OldUsername != username:
                cursor.execute(
                    "UPDATE users SET firstname=%s,lastname=%s,username=%s WHERE id=%s", (firstname, lastname, username, id,))
            else:
                cursor.execute(
                    "UPDATE users SET firstname=%s,lastname=%s WHERE id=%s", (firstname, lastname, id,))

    return {"message": f"userid {id} details updated to username:{username}, firstname:{firstname}, lastname:{lastname}"}, 201


@app.delete('/api/deleteuser')
@cross_origin()
def delete_user():
    data = request.get_json()
    id = data["id"]
    with connection:
        with connection.cursor() as cursor:
            cursor.execute("DELETE from users WHERE id = %s", (id,))
            return {"message": f"user {id} deleted"}, 201


@app.put('/api/updatepw')
@cross_origin()
def change_pw():
    data = request.get_json()
    oldPassword = data["oldPassword"]
    newPassword = data["newPassword"]
    id = int(data["id"])
    hashed_new_password = bcrypt.generate_password_hash(
        newPassword).decode('utf-8')
    with connection:
        cursor = connection.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE id = %s", (id,))
        user = cursor.fetchone()
        if user:
            if bcrypt.check_password_hash(user[2], oldPassword):
                cursor.execute(
                    "UPDATE users SET password=%s WHERE id=%s", (hashed_new_password, id,))
                return {"message": "user password updated"}, 201
    return {"message", "password update failed."}, 500

# EXPENSES API


@app.post('/api/seedexpenses')
@cross_origin()
def seed_expense():
    data = request.get_json()
    userid = int(data["userid"])
    category = data["category"]
    expenseName = data["expenseName"]
    expenseInt = int(data["expenseInt"])
    expenseDate = data["expenseDate"]
    expenseComments = data["expenseComments"]

    with connection:
        with connection.cursor() as cursor:
            cursor.execute(DROP_EXPENSES_TABLE)
            cursor.execute(CREATE_EXPENSES_TABLE)
            cursor.execute(
                INSERT_EXPENSE, (userid, category, expenseName, expenseInt, expenseDate, expenseComments))
            return {"message": "expenses table seeded"}, 201


@app.post('/api/viewexpenses')
@cross_origin()
def view_expenses():
    data = request.get_json()
    userid = int(data["userid"])

    with connection:
        with connection.cursor() as cursor:
            cursor.execute(VIEW_EXPENSE_SPECIFIC_USER, (userid,))
            res = cursor.fetchall()
            return res


@app.post('/api/addexpense')
@cross_origin()
def add_expense():
    data = request.get_json()
    userid = int(data["userid"])
    category = data["category"]
    expenseName = data["expenseName"]
    expenseInt = int(data["expenseInt"])
    expenseDate = data["expenseDate"]
    expenseComments = data["expenseComments"]

    with connection:
        with connection.cursor() as cursor:
            cursor.execute(
                INSERT_EXPENSE, (userid, category, expenseName, expenseInt, expenseDate, expenseComments))
            return {"message": "expense added"}, 201


@app.delete('/api/deleteexpense')
@cross_origin()
def delete_expense():
    data = request.get_json()
    id = data['id']
    with connection:
        with connection.cursor() as cursor:
            cursor.execute("DELETE from EXPENSES WHERE id = %s", (id,))
            return {"message": "expense deleted"}, 201


if __name__ == "__main__":
    app.run(debug=True, port=8000)
