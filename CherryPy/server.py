import cherrypy
import urllib.request
import json
import base64
import nacl.signing
import nacl.encoding
import jinja2
import time
import nacl.secret
import nacl.utils
import sqlite3
import subprocess
import shlex
from subprocess import check_output
import nacl.pwhash
import socket
import ast

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
        return self.login_page()
        #return self.broadcast()

    ############################################
    #open the seperate page files
    @cherrypy.expose
    def login_page(self):
        return open("login.html")

    @cherrypy.expose
    def broadcast(self):
        return open("broadcast.html")

    @cherrypy.expose
    def messages(self):
        return open("messages.html")
    
    @cherrypy.expose
    def settings(self):
        return open("settings.html")

    @cherrypy.expose
    def account_Info(self):
        return open("account_Info.html")

    ###########################################

    """ @cherrypy.expose
    def login(self):
        Page = startHTML 
        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password!</font>"
            
        Page += '<form action="/signin" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br/>'
        Page += 'Password: <input type="text" name="password"/>'
        Page += '<input type="submit" value="Login"/></form>'
        return Page """
    
    @cherrypy.expose    
    def sum(self, a=0, b=0): #All inputs are strings by default
        output = int(a)+int(b)
        return str(output)
        
    # LOGGING IN AND OUT

    @cherrypy.expose
    def call_report(self, status):
        report(status)

    @cherrypy.expose
    def signin(self, username, password, uniquePass):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = authoriseUserLogin(username, password,uniquePass)
        if error == 0:
            cherrypy.session['username'] = username
            raise cherrypy.HTTPRedirect('/broadcast')
        else:
            raise cherrypy.HTTPRedirect('/login_page')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        print("pre signout \n")
        report("offline")
        print("post signout")
        if username is None:
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/login_page')
    
    @cherrypy.expose
    def tx_broadcast(self,message):
        #print(message)
        list_connection = list_online_users()
        insert_flag=1
        
        for x in list_connection:
            try:
                #if(x=="192.168.20.4:80" or x=="172.23.72.183:12345"):
                #    continue  
                
                print("ping check this ip \n")
                print(x)
                print(type(x))
                responding = ping_check(x)
                print(responding)
                print(type(responding))
                if(responding['response'] == "ok"):
                    #print("entered if")
                    #have a condition here later which checks for sending to self and avoid that
                    #something like if x==my_ip
                    rx_broadcast(message,x, insert_flag)
                    #print("after broadcast \n")
                    insert_flag=0
                    #print("Broadcasting")
            except:
                print("try.catch activated")
                continue

    @cherrypy.expose
    def send_private_message(self, upi, message):
        # json.loads to convert JSON array to python list
        #response = json.loads(parcel)

        
        flagging = 0

        #insert flagging 0 for inserting
        insert_flagging = 0

        ip_address_gotten, pkey = get_user_ip_address(upi) 
        print(ip_address_gotten)
        print(upi)
        print(message)
        responding = ping_check(ip_address_gotten)
        print(responding)
        print(type(responding))
        try:
            if(responding['response'] == "ok"):
                rx_privatemessage(message, ip_address_gotten, pkey, upi, insert_flagging)
                flagging =1
        #############################
        except:
            print("except of try catch after checking for response")

        if(flagging == 0):
            list_connection = list_online_users()
            
            for x in list_connection:
                try:
                    #if(x=="192.168.20.4:80" or x=="172.23.72.183:12345"):
                    #    continue  
                    
                    print("ping check this ip \n")
                    print(x)
                    print(type(x))
                    responding = ping_check(x)
                    print(responding)
                    print(type(responding))
                    if(responding['response'] == "ok"):
                        #print("entered if")
                        #have a condition here later which checks for sending to self and avoid that
                        #something like if x==my_ip
                        #upi, pkey = get_user_upi_pkey(x)
                        rx_privatemessage(message, x, pkey, upi, insert_flagging)
                        insert_flagging = 1
                        #print("after broadcast \n")
                        #insert_flag=0
                        #print("Broadcasting")
                except:
                    print("try.catch activated")
                    continue



        ########################33

    @cherrypy.expose
    def get_database_messages(self):
        #print(print_broadcast_messages())
        return print_broadcast_messages_username()

    @cherrypy.expose
    def get_online_people(self):
        JSON_object=list_users()
        user_info=(JSON_object['users'])
        user_list = []
        
        for x in user_info:
            user_list.append(x['username']+ "/n")
            """ #print("user detected  ")
            print(x['username'])
            if(x['username']=="crol453"):
                return (x['connection_address']) """
        
        #users = str(users)
        #print(user_list)
        return user_list
    
###########################################################33
#main closes above
######################

#class to handle receiving of apis (i.e. urls with /api)
class Api(object):
    #CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }       


    @cherrypy.expose
    def rx_broadcast(self):
        
        try :
            #json.loads  = loads json object
            #cherry.request.body.read  = requesting url and reading payload
            total_data = json.loads(cherrypy.request.body.read().decode('utf-8'))
            print(type(total_data))
            print(total_data)

            reply = { 
                "response" : "ok"
            }
 

            loginserver_record= total_data['loginserver_record']

            if(loginserver_record[0:4] == "admin" or loginserver_record[0:5] == "admin"):
                upi = "admin"
            else:
                upi = loginserver_record[0:7]
            
            message_value = total_data['message']
            sender_created_at = total_data['sender_created_at']
            signature = total_data['signature']

            total_data = str(total_data)

            if("fuck" in message_value or "shit" in message_value or "asshole" in message_value or "dick" in message_value or "bhenc" in message_value):
                reply = { 
                "response" : "error"
                }
                return(json.dumps(reply))

            if(upi == "sbha375" or upi == "pmal123" or upi == "jsay091"):
                reply = { 
                "response" : "error"
                }
                return(json.dumps(reply))

            #replace with username later
            if(upi == "ddhy609"):
                print("No need to send to yourself")
            else:
                db_create_broadcast()
                db_insert_broadcast(loginserver_record, upi, message_value, sender_created_at, signature, total_data)
        
        except :
            reply = { 
                "response" : "error"
            }


        return(json.dumps(reply))

    #MOVE DECRYPTION OUT later and make a helper function
    @cherrypy.expose
    def rx_privatemessage(self):
        #json.loads  = loads json object
        #cherry.request.body.read  = requesting url and reading payload
        total_data = json.loads(cherrypy.request.body.read()) #.decode('utf-8'))
        message_received = total_data['encrypted_message']
        
        key=b'c3efb78f4d0bb9bdfbf938aa870ad92298f53e4e0d13b951bcc8f5ac877dc627'
        #key = cherrypy.session.get('hex_key')
        #print(key + " \n \n \n")
        #key = bytes(key, encoding='utf-8')
        #print(key)

        signing_key=nacl.signing.SigningKey(key,encoder=nacl.encoding.HexEncoder)
        publickey= signing_key.to_curve25519_private_key()
        sealed_box=nacl.public.SealedBox(publickey)
        
        #decoded message in bytes
        try:
            message_decrypted = sealed_box.decrypt(message_received,encoder=nacl.encoding.HexEncoder)
            m_decode = message_decrypted.decode('utf-8')
            reply = { 
            "response" : "ok"
            }
            message_gotten = m_decode
        except:
            m_decode = "message couldn't be decrypted"
            reply = { 
            "response" : "Verify you are sending to right person. Message couldn't be decrypted."
            }
            message_gotten = total_data['encrypted_message']



        loginserver_record= total_data['loginserver_record']
        target_pubkey = total_data['target_pubkey']
        target_username = total_data['target_username']
        message_value = message_gotten
        sender_created_at = total_data['sender_created_at']
        #print(sender_created_at)
        signature = total_data['signature']

        total_data = str(total_data)
        
        #replace with username later
        if(target_username == cherrypy.session.get('username')):
            print("No need to message yourself")
        else:
            db_create_message()
            db_insert_message(loginserver_record, target_pubkey, target_username, message_received, sender_created_at, signature, total_data)


        #decoded message in string
        print(message_received) 
        #print(message_decrypted)
        print(m_decode)

        return(json.dumps(reply))

    @cherrypy.expose
    def checkmessages(self, since=str(time.time())): 
        #change above line from since to a default value as well in case blank is passed into since  
        try:
            #message_decrypted = sealed_box.decrypt(message_received,encoder=nacl.encoding.HexEncoder)
            #m_decode = message_decrypted.decode('utf-8')
            array_b = retrieve_from_db_broadcast(since)
            print(array_b)
            array_m = retrieve_from_db_message(since)
            print(array_m)
            reply = { 
                "response" : "ok",
                "broadcasts" : array_b,
                "private_messages" : array_m
            }
            
            #message_gotten = m_decode
        except:
            #m_decode = "message couldn't be decrypted"
            reply = { 
                "response" : "User is not sending data back"
            }
            #message_gotten = message['encrypted_message']
        

        return(json.dumps(reply))

    @cherrypy.expose
    def ping_check(self):
        try:
            reply = {
                "response" : "ok",
                "my_time" : str(time.time())
            }
        except:
            reply = {
                "response" : "error",
                "my_time" : str(time.time())
            }
        return (json.dumps(reply))


    @cherrypy.expose
    def rx_groupinvite(self):
        try:
            reply = {
                "response" : "ok",
                #"my_time" : str(time.time())
            }
        except:
            reply = {
                "response" : "error",
                #"my_time" : str(time.time())
            }
        return (json.dumps(reply))

### Functions only after here
###
#####

def ping():
    url = "http://cs302.kiwi.land/api/ping"

    #STUDENT TO UPDATE THESE...
    #username = "ddhy609"
    #password = "DevashishDhyani_364084614"


    # Generate a new random signing key
    #signing_key = nacl.signing.SigningKey.generate()
    #hexkey= b'2da036038dc32976d9d3b0126bddfc93cd6e3ef0327eac0cd678b941848de308'
    ###Not really needed
    #hex_key = signing_key.encode(encoder=nacl.encoding.HexEncoder)
    #hex_key = b'c3efb78f4d0bb9bdfbf938aa870ad92298f53e4e0d13b951bcc8f5ac877dc627'
    hex_key = cherrypy.session.get('hex_key')
    #hex_key = b'a0251f5f930887567b0ca34611fbf23d7b6dc55b4d7b6006889661112610c55b'
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
   
    headers = {
        'X-username': cherrypy.session.get('username'),
        'X-apikey':cherrypy.session.get('api_key'),
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

    return JSON_object

def report(status):

    url = "http://cs302.kiwi.land/api/report"

    #STUDENT TO UPDATE THESE...
    #username = "ddhy609"
    #password = "DevashishDhyani_364084614"

    ip_val = get_IP()

    #hex_key = signing_key.encode(encoder=nacl.encoding.HexEncoder)
    #hex_key = b'c3efb78f4d0bb9bdfbf938aa870ad92298f53e4e0d13b951bcc8f5ac877dc627'
    hex_key = cherrypy.session.get('hex_key')
    signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)
    print(hex_key)
    #######


    # Sign a message with the signing key

    # Obtain the verify key for a given signing key
    verify_key = signing_key.verify_key

    # Serialize the verify key to send it to a third party
    #verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)

    ####copied from hints
    pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')

    #message_bytes = bytes(pubkey_hex_str, encoding='utf-8')

    #signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    #signature is basically hash. Used to verify pub key is related to private key
    #signature_hex_str = signed.signature.decode('utf-8')
    ####

    #create HTTP BASIC authorization header
    headers = {
        'X-username': cherrypy.session.get('username'),
        'X-apikey':cherrypy.session.get('api_key'),
        'Content-Type' : 'application/json; charset=utf-8',
    }
   

    payload = {
        "connection_address" : ip_val + ":10013",
        "connection_location" : "0",
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
    return JSON_object['response']

def add_pubkey():
    url = "http://cs302.kiwi.land/api/add_pubkey"

    #STUDENT TO UPDATE THESE...
    #username = "ddhy609"
    #password = "DevashishDhyani_364084614"


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

    headers = {
        'X-username': cherrypy.session.get('username'),
        'X-apikey':cherrypy.session.get('api_key'),
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

def check_pubkey():
    #STUDENT TO UPDATE THESE...
    


    #hex_key = signing_key.encode(encoder=nacl.encoding.HexEncoder)
    #hex_key = b'c3efb78f4d0bb9bdfbf938aa870ad92298f53e4e0d13b951bcc8f5ac877dc627'
    hex_key = cherrypy.session.get('hex_key')
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


    ##can be used to get details of passed pubkey
    url = "http://cs302.kiwi.land/api/check_pubkey?pubkey="+pubkey_hex_str

    message_bytes = bytes(pubkey_hex_str, encoding='utf-8')

    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    #signature is basically hash. Used to verify pub key is related to private key
    signature_hex_str = signed.signature.decode('utf-8')
    ####

    headers = {
        'X-username': cherrypy.session.get('username'),
        'X-apikey':cherrypy.session.get('api_key'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {
        #url has get request
    }
    payload = json.dumps(payload).encode('utf-8')

    #STUDENT TO COMPLETE:
    #1. convert the payload into json representation, 
    #2. ensure the payload is in bytes, not a string

    #3. pass the payload bytes into this function
    try:
        req = urllib.request.Request(url, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)

def rx_broadcast(message, ip_user, insert_flag):
    #########################################################3
    #cs302.kiwi.land needs to be replaced by IP address+ListeningPort of receiver
    IPFeneel= "172.23.114.169:1234"
    IPAdmin = "210.54.33.182:80"
    IPLaksh = "172.23.186.227:10001"
    url = "http://"+ ip_user +"/api/rx_broadcast"

    


    #space after emoji required to allow for overlap b/w emoji and text
    #hex_key = b'c3efb78f4d0bb9bdfbf938aa870ad92298f53e4e0d13b951bcc8f5ac877dc627'
    hex_key = cherrypy.session.get('hex_key')
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
    server_time= str(time.time())
    message_bytes = bytes(login_record + message + server_time, encoding='utf-8')

    

    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')

    headers = {
        'X-username': cherrypy.session.get('username'),
        'X-apikey':cherrypy.session.get('api_key'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {
        "loginserver_record" : login_record,
        "message" : message,
        "sender_created_at" : server_time,
        "signature" : signature_hex_str
    }

   
    payload = json.dumps(payload).encode('utf-8')

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

    #may need a workaround stroing username later
    upi = cherrypy.session.get('username')

    #confirm that a broadcast is only being stored once you only enter your message once
    try:  
        print("entered broadcasting try")
        if(JSON_object['response'] == "ok"): 
            print("entered if of braodcasting try")
            if(insert_flag == 1):
                print("insert = 1 here")
            #insert payload as a string
                db_insert_broadcast(login_record, upi, message, server_time, signature_hex_str, payload)
                print("post insert into broadcast")
    except:
        print("Not broadcasting to the given user")

    print(JSON_object)      
   
def list_users():
    url = "http://cs302.kiwi.land/api/list_users"

    

    headers = {
        'X-username': cherrypy.session.get('username'),
        'X-apikey':cherrypy.session.get('api_key'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {
        
    }
    payload = json.dumps(payload).encode('utf-8')

    #STUDENT TO COMPLETE:
    #1. convert the payload into json representation, 
    #2. ensure the payload is in bytes, not a string

    #3. pass the payload bytes into this function
    try:
        req = urllib.request.Request(url, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))
    #print(JSON_object)
    print("List users in")
    print("\n")
    return(JSON_object)

def authoriseUserLogin(username, password, uniquePass):
    try:
        cherrypy.session['username']=username

        print("goes into authorise login")
        print(username)
        print(password)
        print(uniquePass)
        #sign in flow
        #get private data
        
        #load new api key and add it to the session
        api_key_response=load_new_apikey(username,password)
        print(api_key_response)
        if api_key_response['response']=="ok":
            print("stored api_key to session")
            cherrypy.session['api_key']=api_key_response['api_key']
            get_privatedata(username,password,uniquePass)
        else:
            return 1    
        print("trying to ping")
        ping_response = ping()
        print("ping response")
        print(ping_response)
        if(ping_response['signature'] == "ok" and ping_response['response'] == "ok"):
            print("trying to report")
            response=report("online")
            if (response =="ok"):
                #getting_messages()
                print("report response ok")
                print("trying get private data")

                return 0
            else:
                return 1

        else:
            return 1
    except:
        return 1
    #for succesful login, return 0
    #print(store_ping_response)

#targetpubkeys and all that stuff needs to be passed as inputs here
def rx_privatemessage (message, ip_add, pkey, upi, flagging):
    ##need to update later to allow for user to user messaging. Atm, just hammonds client.
    url = "http://"+ ip_add + "/api/rx_privatemessage"   #rx_privatemessage"

    #temp_returning = 0
    message = bytes(message,encoding='utf-8')
    #oberoi pubkey = d76697455341f10649c6ac6241db51c3cc5a2bb9212384b0b3b21bddca1f6a87
    #feneel pubkey = 78123e33622eb039e8c20fb30713902c37bf9fe4493bd1e16e69cd8cc129e03e
    target_pubkey = pkey
    target_username = upi

    #message = bytes("WE got this! \U0001F637  !!!!", encoding='utf-8')
    # Generate a new random signing key
    #hex_key = b'c3efb78f4d0bb9bdfbf938aa870ad92298f53e4e0d13b951bcc8f5ac877dc627'
    hex_key = cherrypy.session.get('hex_key')
    #print(type(hex_key) + "\n \n \n \n \n \n \n"+ "original")

    #hexadecimal_key = cherrypy.session.get('hex_key')
    #hexadecimal_key = bytes(hexadecimal_key, encoding = 'utf-8')
    #print(type(hexadecimal_key) + "\n \n \n \n \n \n \n"+ "bytes hopefully?")
    
    signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)

    time_stamp = str(time.time())

    # Sign a message with the signing key

    # Obtain the verify key for a given signing key
    verify_key = signing_key.verify_key
    
    # Serialize the verify key to rx_prx_prx_psend it to a third party
    #verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)

    pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
    #pubkey_hex_str = pubkey_hex.decode('utf-8')

    login_record = "ddhy609,e91e6780af87f41217d4be94bb6398a027e2c0e28bb0370c414abb9c952399fd,1558592327.9529357,8cecc3bfb3b9739fc4c443f61d36f23184099b758ba6c8a93c3946b8c067bf56b931205e9d713a1818d63ff5540e33959ad350046c598639b2a3abad2d191605"
    #server_time="1558592327.9529357"


    ##############
    #Encrypting public key of target user
    verifykey_target = nacl.signing.VerifyKey(target_pubkey, encoder=nacl.encoding.HexEncoder)
    target_pkey = verifykey_target.to_curve25519_public_key()
    sealed_box = nacl.public.SealedBox(target_pkey)
    encrypted = sealed_box.encrypt(message, encoder=nacl.encoding.HexEncoder)
    message_encrypted = encrypted.decode('utf-8')
    print(message_encrypted)
    ######

    ######
    #Getting signature

    message_bytes = bytes(login_record + target_pubkey + target_username +
        message_encrypted + time_stamp
        , encoding='utf-8')

    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')

    headers = {
        'X-username': cherrypy.session.get('username'),
        'X-apikey':cherrypy.session.get('api_key'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {
        "loginserver_record" : login_record,
        "target_pubkey" : target_pubkey,
        "target_username" : target_username,
        "encrypted_message" : message_encrypted,
        "sender_created_at" : time_stamp,
        "signature" : signature_hex_str
    }
    payload = json.dumps(payload).encode('utf-8')

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

    try:  
        if(JSON_object['response'] == "ok"): 
            #insert payload as a string
                print("pre -insert of message")
                if(flagging == 0):
                    db_insert_message(login_record, target_pubkey, target_username, message_encrypted, time_stamp, signature_hex_str, payload)
                    #temp_returning = 1
    except:
        print("Not broadcasting to the given user")

    print(JSON_object) 
        
    #return temp_returning
    #print(JSON_object)

#creates a db and only creates table if not present
def db_create_message():
    #create my.db if it does not exist, if exists just connects to it
    conn = sqlite3.connect("messages.db")
    #to interact with db get the cursor
    c=conn.cursor()


    c.execute("""
                create table if not exists message (id integer primary key autoincrement not null,
                loginserver_record text not null,
                target_pubkey text,
                target_username text,
                message text,
                sender_created_at text not null,
                signature text not null,
                total_data text not null)
            """
                )
                

    conn.commit()            


    #close db
    conn.close


def db_create_broadcast():
    #create my.db if it does not exist, if exists just connects to it
    conn = sqlite3.connect("messages.db")
    #to interact with db get the cursor
    c=conn.cursor()


    c.execute("""
                create table if not exists broadcast (id integer primary key autoincrement not null,
                loginserver_record text not null,
                upi text not null,
                message text,
                sender_created_at text not null,
                signature text not null,
                total_data text not null)
            """
                )
                

    conn.commit()            


    #close db
    conn.close

#allows to insert into db
def db_insert_message(loginserver_record, target_pubkey, target_username, message_value, sender_created_at, signature, total_data):
    #create my.db if it does not exist, if exists just connects to it
    conn = sqlite3.connect("messages.db")
    #to interact with db get the cursor
    c=conn.cursor()


    c.execute(" insert into message (loginserver_record, target_pubkey, target_username, message,sender_created_at, signature, total_data) values (?,?,?,?,?,?,?)",
                  (loginserver_record, target_pubkey, target_username, message_value, sender_created_at, signature, total_data))
 
                

    conn.commit()            


    #close db
    conn.close()


def db_insert_broadcast(loginserver_record, upi, message_value, sender_created_at, signature, total_data):
    #create my.db if it does not exist, if exists just connects to it
    conn = sqlite3.connect("messages.db")
    #to interact with db get the cursor
    c=conn.cursor()


    c.execute(" insert into broadcast (loginserver_record, upi, message,sender_created_at, signature, total_data) values (?,?,?,?,?,?)",
                  (loginserver_record, upi, message_value, sender_created_at, signature, total_data))
 
    conn.commit()            

    #close db
    conn.close()

#i doubt this is being used right now
def get_user_pubkey_and_status (upi):
    users_object = list_users()
    all_users = users_object['users']
    #array_store = []

    for x in all_users :
        #array_store.append(x['username'])
        if(x['username'] == upi):
            if(x['status'] == "online"):
                print(x['incoming_pubkey'])
                print("upi online")

                break

    #print (array_store)

#need to run a loop to check for only entries after SINCE
def retrieve_from_db_message (since) :
    #create my.db if it does not exist, if exists just connects to it
    conn = sqlite3.connect("messages.db")
    #to interact with db get the cursor
    c=conn.cursor()

    #created_at is a real number does not return anything if it is 0
    #DO NOT DO SELECT* as it selects all the data bad practice
    # SQL INJECTION HANDLED by passing in username and password and using ?? 
    c.execute("""
            SELECT 
            total_data from message""") 
            #WHERE sender_created_at=?  
            #""",(since)
            #    )
                
    array_message = []
    rows=c.fetchall()
    for row in rows:  
        y=eval(row[0])     
        array_message.append(y)  
        

    #getting the values out becoz for some reason I have a double array
    #array_message = array_message[0]

    #close db
    conn.close
    return array_message

def retrieve_from_db_broadcast (since) :
    #create my.db if it does not exist, if exists just connects to it
    conn = sqlite3.connect("messages.db")
    #to interact with db get the cursor
    c=conn.cursor()


    
    #created_at is a real number does not return anything if it is 0
    #DO NOT DO SELECT* as it selects all the data bad practice
    # SQL INJECTION HANDLED by passing in username and password and using ?? 
    c.execute("""
            SELECT 
            total_data, sender_created_at from broadcast""") 
            #WHERE sender_created_at=?  
            #""",(since)
            #    )
                
    array_broadcast = []
    rows=c.fetchall()
    for row in rows:
        #converting to dictionary
        y=eval(row[0]) 
        z=row[1]
        if(float(z) > float(since)):  
            array_broadcast.append(y)

    #getting the values out becoz for some reason I have a double array
    #array_broadcast = array_broadcast[0]

    #close db
    conn.close
    return array_broadcast

def get_IP():
    #ip address extraction
    ip_command = (check_output(["hostname","-I"]))
    ip_string = ip_command.decode('utf-8')
    ip_add = ip_string[0:len(ip_string)-2]
    return(ip_add)

def checkmessages(url_val, time_val):  
    #private_key =b'c3efb78f4d0bb9bdfbf938aa870ad92298f53e4e0d13b951bcc8f5ac877dc627'
    private_key = cherrypy.session.get('hex_key')
    private_key=nacl.signing.SigningKey(private_key, encoder=nacl.encoding.HexEncoder)
    #public key
    public_key=private_key.verify_key
    #changing key to string
    pkey=public_key.encode(nacl.encoding.HexEncoder).decode('utf-8')
    #generated a signature by signing the message (addded pkey+username in bytes then reconvert to hex)
    sign = private_key.sign(bytes(pkey,encoding='utf-8'), encoder=nacl.encoding.HexEncoder)
    #create a string signature
    sig = sign.signature.decode('utf-8')
    

    #url = "http://cs302.kiwi.land/api/checkmessages?since="+(Time)
    #kazuki 172.23.46.106:1234
    #url= "http://172.23.114.169:1234/api/checkmessages?since="+str(Time) #dev
    url = "http://" + url_val + "/api/checkmessages?since="+time_val


    headers = {
        'X-username': cherrypy.session.get('username'),
        'X-apikey':cherrypy.session.get('api_key'),
        'Content-Type' : 'application/json; charset=utf-8',
    }
    
    payload ={
        ##GET REQUEST NO PAYLOAD
    }

    try:
        
        A=json.dumps(payload).encode('utf-8')

        req = urllib.request.Request(url,data=A,headers=headers)
        response = urllib.request.urlopen(req, timeout=1)

        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8')


        JSON_object = json.loads(data.decode(encoding))
        #print(JSON_object)

        broadcast_data = JSON_object['broadcasts']
        message_data = JSON_object['private_messages']

        #need to store x as a string since its a Json object and sql only likes strings
        for x in broadcast_data:
            counting_inserts=0
            loginserver_record = x['loginserver_record']
            message = x['message']
            sender_created_at = x['sender_created_at']
            signature = x['signature']

            #need a way to insert upi here
            if(loginserver_record[0:4] == "admin" or loginserver_record[0:5] == "admin"):
                upi = "admin"
            else:
                upi = loginserver_record[0:7]

            db_insert_broadcast(loginserver_record, upi, message, sender_created_at, signature, str(x))
            counting_inserts= counting_inserts+1
        
            if(counting_inserts >=5):
                break

        for x in message_data:
            counting_inserts=0
            loginserver_record = x['loginserver_record']
            target_pubkey = x['target_pubkey']
            target_username = x['target_username']
            encrypted_message = x['encrypted_message']
            sender_created_at = x['sender_created_at']
            signature = x['signature']

            db_insert_message(loginserver_record, target_pubkey, target_username, encrypted_message, sender_created_at, signature ,str(x))
            counting_inserts= counting_inserts+1
        
            if(counting_inserts >=5):
                break

    except:
        print("Can't insert for this user")

    #print(broadcast_data)
    response.close()

#make changes later
def add_privatedata(uniquepass):
    url = "http://cs302.kiwi.land/api/add_privatedata"

    
    uniquepass = "password"

    unix_time = str(time.time())
    loginserverrecord = 'ddhy609,e91e6780af87f41217d4be94bb6398a027e2c0e28bb0370c414abb9c952399fd,1558592327.9529357,8cecc3bfb3b9739fc4c443f61d36f23184099b758ba6c8a93c3946b8c067bf56b931205e9d713a1818d63ff5540e33959ad350046c598639b2a3abad2d191605'
    #privkey = 'c3efb78f4d0bb9bdfbf938aa870ad92298f53e4e0d13b951bcc8f5ac877dc627'
    privkey=cherrypy.session.get('hex_key')

    privdata = {
        "prikeys": [privkey],
        "blocked_pubkeys" : [],
        "blocked_username" : [],
        "blocked_messages_signatures": [],
        "blocked_words": [],
        "favourite_message_signatures" : [],
        "friends_usernames" : [],
    }

    encrypt_pass = bytes(uniquepass, encoding = 'utf-8')
    salt_pass = bytes((uniquepass*16).encode('utf-8')[:16])

    secret_key = nacl.pwhash.argon2i.kdf(32, encrypt_pass,salt_pass , nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE, 
                nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE)

    box = nacl.secret.SecretBox(secret_key)

    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

    jsonBytes = bytes(json.dumps(privdata), encoding = 'utf-8')

    encrypted_message = (base64.b64encode(box.encrypt(jsonBytes, nonce)))
    privatedata = encrypted_message.decode('utf-8')


    #print (privatedata)

    signing_key = nacl.signing.SigningKey(privkey, encoder=nacl.encoding.HexEncoder)
    message_bytes = bytes(privatedata + loginserverrecord + unix_time, encoding='utf-8')
    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')


    #print (signature_hex_str)

    headers = {
        'X-username': cherrypy.session.get('username'),
        'X-apikey':cherrypy.session.get('api_key'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    print(privatedata)
    print(loginserverrecord)
    print(signature_hex_str)

    payload = {
        "privatedata" : privatedata,
        "loginserver_record" : loginserverrecord ,
        "client_saved_at" : (unix_time),
        "signature" : signature_hex_str
    }
    payload = json.dumps(payload).encode('utf-8')

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

#make changes later
def get_privatedata(username,password,uniquepass):
    url = "http://cs302.kiwi.land/api/get_privatedata"  
    
    
    headers = {
        'X-username': username,
        'X-apikey':cherrypy.session.get('api_key'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {
        
    }
    payload = json.dumps(payload).encode('utf-8')

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

    encoded_string = JSON_object['privatedata'] #extract priavte data from the return parameters

    print(encoded_string)

    encrypt_pass = bytes(uniquepass, encoding = 'utf-8')
    salt_pass = bytes((uniquepass*16).encode('utf-8')[:16])

    secret_key = nacl.pwhash.argon2i.kdf(32, encrypt_pass,salt_pass , nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE, 
                nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE)

    box = nacl.secret.SecretBox(secret_key)

    decrypt_string = box.decrypt(encoded_string, encoder=nacl.encoding.Base64Encoder)

    decode_string = decrypt_string.decode('utf-8')
    
    
    print (decode_string)
    prikeys_now=ast.literal_eval(decode_string)
    prikeys=prikeys_now['prikeys']
    cherrypy.session['prikeys']=prikeys
    cherrypy.session['hex_key']=prikeys[0]
    print("private data is succesfully retrieved from login server")

def ping_check(ip):
    url = "http://"+ ip + "/api/ping_check"

    headers = {
        'X-username': cherrypy.session.get('username'),
        'X-apikey':cherrypy.session.get('api_key'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    ip_value = get_IP()

    payload = {
        "my_time" : str(time.time()),
        #"my_active_usernames" : username,
        "connection_address" : ip_value + ":10013",
        #"connection_address" : "127.0.0.1:8000",
        "connection_location" : "0"
    }

    payload = json.dumps(payload).encode('utf-8')

    try:
        #req = urllib.request.Request(url, data=payload, headers=headers)
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req, timeout=1)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)
        print("try of ping_check")
        return JSON_object
    except:
        print("ping_check exception")
        print(json.dumps({'response': "not ok"}))
        return (json.dumps({'response': "not ok"}))
    
#returning user ips of all online people
def list_online_users():
    user_list = []
    user_ip = []

    try:
        JSON_object=list_users()
        user_info=(JSON_object['users'])
        
        for x in user_info:
            user_list.append(x['username'])
            user_ip.append(x['connection_address'])

        print(user_list)
        print(user_ip)
        print(len(user_info))
        print(len(user_list))
        print(len(user_ip))      
         
    except:
        print("Cant retrieve users")
    
    #users = str(users)
    return (user_ip)   

#returning ip and pkey of given upi if online
def get_user_ip_address (upi):
    users_object = list_users()
    all_users = users_object['users']
    print(all_users)
    value_connect = 0
    value_targetpkey = 0
    try:
        for x in all_users :
            #array_store.append(x['username'])
            if(x['username'] == upi):
                if(x['status'] == "online"):
                    value_connect=(x['connection_address'])
                    value_targetpkey = (x['incoming_pubkey'])

        return value_connect, value_targetpkey
    except:
        return value_connect, value_targetpkey

def print_broadcast_messages_username():
    #create my.db if it does not exist, if exists just connects to it
    conn = sqlite3.connect("messages.db")
    #to interact with db get the cursor
    c=conn.cursor()


    
    #created_at is a real number does not return anything if it is 0
    #DO NOT DO SELECT* as it selects all the data bad practice
    # SQL INJECTION HANDLED by passing in username and password and using ?? 
    c.execute("""
            SELECT 
            upi,message from broadcast""") 
            #WHERE sender_created_at=?  
            #""",(since)
            #    )
                
    rows=c.fetchall()

    string_message=""  

    #reversed
    for row in reversed(rows):
        #converting to dictionary
        #y=eval(row[0])    
        string_message = string_message + row[0] + " : " + row[1] + "/n" + "/n"
        #string_upi = string_upi + column[0] + "/n"
        #string_combined = string_combined +string_message+string_upi
  

    #getting the values out becoz for some reason I have a double array
    #array_broadcast = array_broadcast[0]

    #close db
    conn.close
      
    #print(array_message)
    
    #going from 0 to -2 to get rid of the last /n value
    string_message = string_message[0:-2]
    return (string_message)


def get_user_upi_pkey (ip_add):
    users_object = list_users()
    all_users = users_object['users']
    print(all_users)
    value_upi = 0
    value_targetpkey = 0
    try:
        for x in all_users :
            #array_store.append(x['username'])
            if(x['connection_address'] == ip_add):
                if(x['status'] == "online"):
                    value_upi=(x['username'])
                    value_targetpkey = (x['incoming_pubkey'])

        return value_upi, value_targetpkey
    except:
        return value_upi, value_targetpkey

def load_new_apikey(username,password):
    
    url = "http://cs302.kiwi.land/api/load_new_apikey"
    #create request and open it into a response object

    #create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    req = urllib.request.Request(url,headers=headers)
    response = urllib.request.urlopen(req)

    #read and process the received bytes
    data = response.read() 
    encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
    response.close() #be a tidy kiwi
    JSON_object = json.loads(data.decode(encoding))
    print("load api key done successful")
    #print(JSON_object)
    return JSON_object
    
def getting_messages():
    try:
        JSON_object=list_users()
        user_info=(JSON_object['users'])
        
        for x in user_info:
            checkmessages(x['connection_address'], "1560140943.320333")
    except:
        print("can't retrieve messages from given user")