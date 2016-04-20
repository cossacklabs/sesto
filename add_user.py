#/usr/bin/python3.5
#
# Copyright (c) 2016 Cossack Labs Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import sqlite3
import sys
from pythemis import scell
import binascii
import base64

if len(sys.argv) != 3:
    print("Usage: add_user.py <username> <password>");
    exit();

dbconn = sqlite3.connect('sesto.db');
c = dbconn.cursor()

try:
    c = dbconn.cursor()
    # Create table
    c.execute('''CREATE TABLE users (user text, password text, root_id blob)''');
    c.execute('''CREATE TABLE data (id INTEGER PRIMARY KEY AUTOINCREMENT, data blob)''');
    dbconn.commit()
except sqlite3.OperationalError:
    a=1;

c.execute('SELECT user FROM users WHERE user=?', [sys.argv[1]]);
if c.fetchone() is not None:
    print("User with name \"{}\" is always present in db".format(sys.argv[1]))
else:
    enc=scell.scell_seal(sys.argv[2].encode('utf8'))
    c.execute("INSERT INTO data (data) VALUES (?)", [sqlite3.Binary(enc.encrypt(base64.b64encode(b"{ \"type\":\"folder\",\"name\": \"root\", \"desc\":\"root folder\",\"context\": []}"), sys.argv[1].encode('utf8'))), ] );
    c.execute("Insert INTO users (user, password, root_id) VALUES (?, ?, ?)", [sys.argv[1], sys.argv[2], sqlite3.Binary(enc.encrypt(c.lastrowid.to_bytes(4, byteorder='big'), sys.argv[1].encode('utf8'))), ]);
    dbconn.commit()
    print("user \"{}\" added successfully".format(sys.argv[1]));