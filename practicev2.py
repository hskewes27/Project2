from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta, timezone
import base64
import json
import sqlite3
from pathlib import Path
import jwt  # this is the import I am having problems with I keep getting a "JWT encoding error: module 'jwt' has no attribute
# 'encode'" error even though I have the correct pyjwt installed like a lot of online forums say to do.
import logging

# Configure logging so I can see what is actually happening in the code
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Server settings
hostName = "localhost"
serverPort = 8080

# Database setup // this just makes sure the private file goes into the right directory
script_dir = Path(__file__).parent
local_db_path = script_dir / "totally_not_my_privateKeys.db"


# connects this program to the database and creates the table to file into
def connect_db():
    conn = sqlite3.connect(local_db_path, check_same_thread=False)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    return conn, cursor


conn, cursor = connect_db()


def store_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # this is code from the skeleton that I could have misunderstood after read throughs
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    expired_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    valid_exp_time = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
    expired_exp_time = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
    # Insert keys and fetch the generated kid
    # I watched youtube videos on this part inserting and
    # creating the database. That part is not hard.
    # I just struggle with implementing jwk into it
    cursor.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        (sqlite3.Binary(pem), valid_exp_time)
    )
    valid_kid = cursor.lastrowid

    cursor.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        (sqlite3.Binary(expired_pem), expired_exp_time)
    )
    expired_kid = cursor.lastrowid

    conn.commit()
    logging.info(f"Keys generated and stored: Valid KID={valid_kid}, Expired KID={expired_kid}")


store_keys()
# Skeleton code from project1 zip


def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    return base64.urlsafe_b64encode(value_bytes).rstrip(b'=').decode('utf-8')


# this is the most confusing section for me I think the main issue
# could be with the encoding and decoding from the database
class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":  # key check
            is_expired = 'expired' in params  # expired key check
            query = "SELECT kid, key FROM keys WHERE exp {} ? ORDER BY exp {} LIMIT 1".format(
                "<" if is_expired else ">", "DESC" if is_expired else "ASC"
            )
            cursor.execute(query, (int(datetime.now(timezone.utc).timestamp()),))

            row = cursor.fetchone()
            if not row:  # checks for no key
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Key not found")
                logging.error("Key not found.")
                return

            kid, pem_key = row
            logging.info(f"Selected KID={kid} for signing JWT.")

            try:
                private_key = serialization.load_pem_private_key(
                    pem_key, password=None, backend=default_backend()
                )
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Key loading error: {str(e)}".encode("utf-8"))
                logging.error(f"Key loading error: {str(e)}")
                return

            token_payload = {
                "user": "username",
                "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
                if not is_expired else int(
                    (datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()
                )
            }

            headers = {"kid": str(kid)}
            try:
                jwt_token = jwt.encode(
                    token_payload, private_key, algorithm="RS256", headers=headers
                )
                logging.info(f"Issued JWT: {jwt_token}")
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"JWT encoding error: {str(e)}".encode("utf-8"))
                logging.error(f"JWT encoding error: {str(e)}")
                return

            # Include JWT in the response body as both raw string and JSON format
            response_body = {
                "token": jwt_token,
                "jwt": jwt_token
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response_body).encode("utf-8"))
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            # gets kid
            cursor.execute("SELECT kid, key FROM keys")
            keys = cursor.fetchall()

            jwks = {"keys": []}
            for kid, pem_key in keys:
                private_key = serialization.load_pem_private_key(
                    pem_key, password=None, backend=default_backend()
                )
                public_key = private_key.public_key()
                public_numbers = public_key.public_numbers()

                jwks["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(public_numbers.n),
                    "e": int_to_base64(public_numbers.e),
                })

            self.wfile.write(json.dumps(jwks).encode("utf-8"))
            logging.info(
                "Served JWKS endpoint."
            )  # im not sure why but this log never goes out
            # I think this implies the code breaks down in post
            return

        self.send_response(405)
        self.end_headers()


if __name__ == "__main__":  # runs server
    webServer = HTTPServer((hostName, serverPort), MyServer)
    logging.info(f"Server started at http://{hostName}:{serverPort}")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()
    logging.info("Server stopped.")
