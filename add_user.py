#/usr/bin/python3.5
#
# Copyright (c) 2015 Cossack Labs Limited
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
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