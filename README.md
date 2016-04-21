# SESTO

Sesto (abbreviation for Secret Store) is open source passwords (and general secrets) manager for web. 

Read [blog post](https://www.cossacklabs.com/presenting-sesto.html) for description of Sesto, it's security model, architecture and some background experience. 

Sesto is a proof-of-concept tool developed during Themis/WebThemis development to see how easy would it be to build sophisticated security schemes. 

Sesto is licensed as Apache2 Open Source software.

**WARNING**: Sesto is proof-of-concept code. For industrial usage, it requires significant changes: some proper HTTP server (right now it runs on top of aiohttp), server authentication for client, shared secret management and a lot of infrastructure around. If you're interested in developing something more practical on top of Sesto, feel free to fork the project and drop us a line for help, we'll be glad to. 

# Installing Sesto

To run Sesto, you will need three things: 

1. Themis library compiled with Secure Comparator support 
2. Python 3.4+
3. libssl-dev installed

```
git clone https://github.com/cossacklabs/themis
cd themis
make SECURE_COMPARATOR=enable
sudo make  SECURE_COMPARATOR=enable insall
cd ..
git clone https://github.com/cossacklabs/sesto
cd sesto
pip3 install -r requirements.txt
python3 add_user.py test_user test_pass
```

# Running Sesto

```
python3 server.py
```

or 

```
python3 server.py -v 
```

to actually see what's going on. 

Server will run on port 5103 of the machine you've launched it on.

## Test data

There's a test user: 

```
login: testuser
password: testpass
```

with test database to play around.
