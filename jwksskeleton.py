from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta, timezone
import base64
import json
import jwt
import sqlite3
import pathlib

hostName = "localhost"
serverPort = 8080

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

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

numbers = private_key.private_numbers()

#connecting the db
def connecttodb(local_db_path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(local_db_path)
    cursor = connection.cursor()
    return connection, cursor
def create_table(cursor, conn):
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys (
    kid TEXT PRIMARY KEY,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL)''')
    conn.commit()
#commit info to db
def committodb(cursor, conn, pem, expired_pem):
    cursor.execute("INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)",
               ("goodKID", sqlite3.Binary(bytes(pem)), int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())))
    cursor.execute("INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)",
               ("expiredKID", sqlite3.Binary(bytes(expired_pem)), int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())))
    conn.commit()
def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):                #my euid is hj0100
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            kid = "goodKID"
            token_payload = {
                "user": "username",
                "exp": datetime.now(timezone.utc) + timedelta(hours=1)
            }
            if 'expired' in params:
                kid = "expiredKID"
                token_payload["exp"] = datetime.now(timezone.utc) - timedelta(hours=1)
            cursor.execute("SELECT key FROM keys WHERE kid=?", (kid,))
            priv_key_record = cursor.fetchone()
            if priv_key_record:
                priv_key = priv_key_record[0]  # Assuming `key` column contains the PEM key
                private_key = serialization.load_pem_private_key(priv_key, password=None)            
            else:
            # Handle the case where the key doesn't exist for the given kid
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Kid not found")
                return
            
            private_key = serialization.load_pem_private_key(priv_key.encode(), password=None)
            encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers={"kid": kid})
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            cursor.execute("SELECT kid, key FROM keys")
            keys = cursor.fetchall()
            jwks = {"keys": []}
            for key_record in keys:
                kid = key_record[0]
                priv_key_pem = key_record[1]

                private_key = serialization.load_pem_private_key(priv_key_pem.encode(), password=None)
                public_key = private_key.public_key()
                public_numbers = public_key.public_numbers()
                jwks["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": kid,
                    "n": int_to_base64(public_numbers.n),
                    "e": int_to_base64(public_numbers.e),
                })
            self.wfile.write(bytes(json.dumps(jwks), "utf-8"))


if __name__ == "__main__":
    #creating the connection between the program an sqlite db
    local_db_path = "./totally_not_my_private_keys.db"
    conn, cursor = connecttodb(local_db_path)
    #sending data over to the db
    create_table(cursor, conn)
    committodb(cursor, conn, pem, expired_pem)

    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
