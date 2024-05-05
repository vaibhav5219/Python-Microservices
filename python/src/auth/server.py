import jwt, datetime, os
from flask import Flask, request
from flask_mysqldb import MySQL

server = Flask(__name__)
mysql = MySQL(server)

#config
server.config["MYSQL_HOST"] = 'localhost' # os.environ.get("MYSQL_HOST")
server.config["MYSQL_USER"] = 'localhost' # os.environ.get("MYSQL_USER")
server.config["MYSQL_PASSWORD"] = 'localhost' # os.environ.get("MYSQL_PASSWORD")
server.config["MYSQL_DB"] = 'localhost' # os.environ.get("MYSQL_DB")
server.config["MYSQL_PORT"] = 'localhost' # os.environ.get("MYSQL_PORT")
print(server.config["MYSQL_HOST"])

@server.route("/login", methods=["POST"])
def login():
    auth = request.authorization
    if not auth:
        return "missing credentials", 401
    
    # check db for username and password
    cur = mysql.connection.cursor()
    res =  cur.execute(
        "SELECT email, password FROM user WHERE email=%s", (auth.username,)
    )

    if res>0:
        user_row = cur.fetchone()
        email = user_row[0]
        password = user_row[1]

        if auth.username != email and auth.password != password:
            return "Invalid credentials", 402
        else:
            return createJWT(auth.usernam, os.environ.get("JWT_SECRET"), True)
    else:
        return "Invalid credentials", 402
    
@server.route("/validate", methods=["POST"])
def validate():
    encoded_jwt = request.headers["Authorization"]
    if not encoded_jwt:
        return "missing credentials", 401
    encoded_jwt = encoded_jwt.split(" ")[1]
    try:
        decoded = jwt.decode(
            encoded_jwt, 
            os.environ.get("JWT_SECRET"),
            algorithm = ["HS256"]
        )
    except:
        return "not authorized",403
    
    return decoded, 200


def createJWT(username, secret, authz): # authz = true => admin
    return jwt.encode(
        {
            "username": username,
            "exp": datetime.datetime.now(tz=datetime.datetime.timezone.utc)
                    + datetime.timedelta(days=1),
            "iat": datetime.datetime.utcnow(),
            "admin": authz,
        },
        secret,
        algorithm = "HS256"
    )

if __name__ == "__main__":
    server.run(host="0.0.0.0", port=5000)
    print(__name__)