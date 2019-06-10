import urllib.request
import json
import base64
import nacl.utils
import nacl.secret
import nacl.signing
import nacl.encoding
import time
import nacl.pwhash

url = "http://cs302.kiwi.land/api/add_privatedata"

#STUDENT TO UPDATE THESE...
username = "ddhy609"
password = "DevashishDhyani_364084614"
uniquepass = "password"

unix_time = str(time.time())
loginserverrecord = 'ddhy609,e91e6780af87f41217d4be94bb6398a027e2c0e28bb0370c414abb9c952399fd,1558592327.9529357,8cecc3bfb3b9739fc4c443f61d36f23184099b758ba6c8a93c3946b8c067bf56b931205e9d713a1818d63ff5540e33959ad350046c598639b2a3abad2d191605'
privkey = 'c3efb78f4d0bb9bdfbf938aa870ad92298f53e4e0d13b951bcc8f5ac877dc627'


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

#create HTTP BASIC authorization header
credentials = ('%s:%s' % (username, password))
b64_credentials = base64.b64encode(credentials.encode('ascii'))
headers = {
    'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
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
