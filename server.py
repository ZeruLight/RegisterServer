#!/usr/bin/python

# pip install psycopg2-binary
# pip install bcrypt
import http.server
import json
import psycopg2
import bcrypt
from datetime import datetime, timedelta

database_password = 'a'
webserver_port = 80


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, conn):
        self.db = conn

    def __call__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def do_GET(self):
        self.path = '/index.html'
        return http.server.SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        try:
            cursor = self.db.cursor()
            content_length = int(self.headers.get('content-length', 0))
            post_data = json.loads(self.rfile.read(content_length))
            insert_user = 'INSERT INTO users (username, password, return_expires) VALUES (%s, %s, %s);'
            password = post_data.get('password')
            byte_password = password.encode('utf-8')
            password_salt = bcrypt.gensalt()
            password_hash = bcrypt.hashpw(byte_password, password_salt).decode('utf-8')
            timestamp = str(datetime.now() + timedelta(days=30))
            cursor.execute(insert_user, (post_data.get('id'), str(password_hash), timestamp))
            self.send_response(200)
            self.send_header('content-type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(json.dumps(0), 'utf-8'))
        except Exception as e:
            print(e, '\n')
            self.send_response(200)
            self.send_header('content-type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(json.dumps(1), 'utf-8'))


connection = psycopg2.connect(
    host='localhost',
    port='5432',
    user='postgres',
    password=database_password,
    dbname='erupe'
)
connection.autocommit = True
server = http.server.HTTPServer(('0.0.0.0', webserver_port), Handler(connection))
print('Listening on port', webserver_port)
server.serve_forever()
