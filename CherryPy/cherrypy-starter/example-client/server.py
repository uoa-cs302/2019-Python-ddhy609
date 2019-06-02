import cherrypy
import urllib.request
import json
import base64
import nacl.signing
import nacl.encoding
import jinja2
import time

startHTML = "<html><head><title>CS302 example</title><link rel='stylesheet' href='/static/example.css' /></head><body>"

#class handling all url without /api
class MainApp(object):

	#CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }       

	# If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self):
        Page = startHTML + "Welcome! This is a test website for COMPSYS302!<br/>"
        
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "Here is some bonus text because you've logged in! <a href='/signout'>Sign out</a>"
        except KeyError: #There is no username
            
            Page += "Click here to <a href='login'>login</a>."
        return Page
        
    @cherrypy.expose
    def login(self, bad_attempt = 0):
        Page = startHTML 
        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password!</font>"
            
        Page += '<form action="/signin" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br/>'
        Page += 'Password: <input type="text" name="password"/>'
        Page += '<input type="submit" value="Login"/></form>'
        return Page
    
    @cherrypy.expose    
    def sum(self, a=0, b=0): #All inputs are strings by default
        output = int(a)+int(b)
        return str(output)
        
    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = authoriseUserLogin(username, password)
        if error == 0:
            cherrypy.session['username'] = username
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if username is None:
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')

#class to handle receiving of apis (i.e. urls with /api)
class Api(object):
    @cherrypy.expose
    def rx_broadcast(self):
        #json.loads  = loads json object
        #cherry.request.body.read  = requesting url and reading payload
        message = json.loads(cherrypy.request.body.read().decode('utf-8'))
        print(message)

        reply = { 
            "response" : "ok"
        }
        
        return(json.dumps(reply))
###
### Functions only after here
###
#####

def ping(username, password):
    url = "http://cs302.kiwi.land/api/ping"

    #STUDENT TO UPDATE THESE...
    username = "ddhy609"
    password = "DevashishDhyani_364084614"


    # Generate a new random signing key
    #signing_key = nacl.signing.SigningKey.generate()
    #hexkey= b'2da036038dc32976d9d3b0126bddfc93cd6e3ef0327eac0cd678b941848de308'
    ###Not really needed
    #hex_key = signing_key.encode(encoder=nacl.encoding.HexEncoder)
    hex_key = b'c3efb78f4d0bb9bdfbf938aa870ad92298f53e4e0d13b951bcc8f5ac877dc627'
    signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)
    print(hex_key)
    #######


    # Sign a message with the signing key

    # Obtain the verify key for a given signing key
    verify_key = signing_key.verify_key

    # Serialize the verify key to send it to a third party
    verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)

    ####copied from hints
    pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')

    message_bytes = bytes(pubkey_hex_str, encoding='utf-8')

    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    #signature is basically hash. Used to verify pub key is related to private key
    signature_hex_str = signed.signature.decode('utf-8')
    ####

    #create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {
        "pubkey" : pubkey_hex_str,
        "signature" : signature_hex_str
    }
    payload = json.dumps(payload).encode('utf-8')

    #STUDENT TO COMPLETE:
    #1. convert the payload into json representation, 
    #2. ensure the payload is in bytes, not a string

    #3. pass the payload bytes into this function
    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)

def report(username, passsword, status):

    url = "http://cs302.kiwi.land/api/report"

    #STUDENT TO UPDATE THESE...
    username = "ddhy609"
    password = "DevashishDhyani_364084614"

    #hex_key = signing_key.encode(encoder=nacl.encoding.HexEncoder)
    hex_key = b'c3efb78f4d0bb9bdfbf938aa870ad92298f53e4e0d13b951bcc8f5ac877dc627'
    signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)
    print(hex_key)
    #######


    # Sign a message with the signing key

    # Obtain the verify key for a given signing key
    verify_key = signing_key.verify_key

    # Serialize the verify key to send it to a third party
    verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)

    ####copied from hints
    pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')

    message_bytes = bytes(pubkey_hex_str, encoding='utf-8')

    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    #signature is basically hash. Used to verify pub key is related to private key
    signature_hex_str = signed.signature.decode('utf-8')
    ####

    #create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {
        "connection_address" : "127.0.0.1:8000",
        "connection_location" : 1,
        "incoming_pubkey" : pubkey_hex_str,
        "status" : status
    }
    payload = json.dumps(payload).encode('utf-8')

    #STUDENT TO COMPLETE:
    #1. convert the payload into json representation, 
    #2. ensure the payload is in bytes, not a string

    #3. pass the payload bytes into this function
    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)

def add_pubkey(username, password):
    url = "http://cs302.kiwi.land/api/add_pubkey"

    #STUDENT TO UPDATE THESE...
    username = "ddhy609"
    password = "DevashishDhyani_364084614"


    # Generate a new random signing key
    signing_key = nacl.signing.SigningKey.generate()
    ###Not really needed
    hex_key = signing_key.encode(encoder=nacl.encoding.HexEncoder)
    print(hex_key)
    #######


    # Sign a message with the signing key

    # Obtain the verify key for a given signing key
    verify_key = signing_key.verify_key

    # Serialize the verify key to send it to a third party
    verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)

    ####copied from hints
    pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')

    message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')

    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    #signature is basically hash. Used to verify pub key is related to private key
    signature_hex_str = signed.signature.decode('utf-8')
    ####

    #create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {
        "pubkey" : pubkey_hex_str,
        "username" : username,
        "signature" : signature_hex_str
    }
    payload = json.dumps(payload).encode('utf-8')

    #STUDENT TO COMPLETE:
    #1. convert the payload into json representation, 
    #2. ensure the payload is in bytes, not a string

    #3. pass the payload bytes into this function
    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)

def rx_broadcast(message):
    url = "http://cs302.kiwi.land/api/rx_broadcast"

    #STUDENT TO UPDATE THESE...
    username = "ddhy609"
    password = "DevashishDhyani_364084614"

    #message = "FINALLY!"
    # Generate a new random signing key
    hex_key = b'c3efb78f4d0bb9bdfbf938aa870ad92298f53e4e0d13b951bcc8f5ac877dc627'
    signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)


    # Sign a message with the signing key

    # Obtain the verify key for a given signing key
    verify_key = signing_key.verify_key


    ts = time.time()
    # Serialize the verify key to send it to a third party
    verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)

    pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')

    login_record = "ddhy609,e91e6780af87f41217d4be94bb6398a027e2c0e28bb0370c414abb9c952399fd,1558592327.9529357,8cecc3bfb3b9739fc4c443f61d36f23184099b758ba6c8a93c3946b8c067bf56b931205e9d713a1818d63ff5540e33959ad350046c598639b2a3abad2d191605"
    server_time="1558592327.9529357"
    message_bytes = bytes(login_record + message + server_time, encoding='utf-8')

    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')

    #create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {
        "loginserver_record" : login_record,
        "message" : message,
        "sender_created_at" : server_time,
        "signature" : signature_hex_str
    }
    payload = json.dumps(payload).encode('utf-8')

    #STUDENT TO COMPLETE:
    #1. convert the payload into json representation, 
    #2. ensure the payload is in bytes, not a string

    #3. pass the payload bytes into this function
    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)


def authoriseUserLogin(username, password):
    print("Log on attempt from {0}:{1}".format(username, password))
    if ((username.lower() == "user") and (password.lower() == "password") or
        (username.lower() == "user1") and (password.lower() == "password1")):
        print("Success")
        return 0
    else:
        print("Failure")
        return 1