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
import nacl.hash


url = "http://172.23.114.169/10050/api/rx_groupinvite"

target_pubkey = "78123e33622eb039e8c20fb30713902c37bf9fe4493bd1e16e69cd8cc129e03e"
target_username = "fsan110"
username = "ddhy609"
password = "DevashishDhyani_364084614"


# Generate a new random signing key
signing_key = nacl.signing.SigningKey.generate()
###Not really needed
hex_key = signing_key.encode(encoder=nacl.encoding.HexEncoder)
print("private key")
print(hex_key)

signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)

# Sign a message with the signing key
# Obtain the verify key for a given signing key
verify_key = signing_key.verify_key

# Serialize the verify key to send it to a third party
verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)

pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
pubkey_hex_str = pubkey_hex.decode('utf-8')
print("public key")
print(pubkey_hex_str)

login_record = "ddhy609,e91e6780af87f41217d4be94bb6398a027e2c0e28bb0370c414abb9c952399fd,1558592327.9529357,8cecc3bfb3b9739fc4c443f61d36f23184099b758ba6c8a93c3946b8c067bf56b931205e9d713a1818d63ff5540e33959ad350046c598639b2a3abad2d191605"

gkey = bytes(pubkey_hex_str, encoding='utf-8')
print("gkey")
print(gkey)

time_stamp = str(time.time())
##############
#Encrypting public key of target user
verifykey_target = nacl.signing.VerifyKey(target_pubkey, encoder=nacl.encoding.HexEncoder)
target_pkey = verifykey_target.to_curve25519_public_key()
sealed_box = nacl.public.SealedBox(target_pkey)
encrypted = sealed_box.encrypt(gkey, encoder=nacl.encoding.HexEncoder)
groupkey_encrypted = encrypted.decode('utf-8')
print("group key encrypted")
print(groupkey_encrypted)
######

######
#Getting signature


groupkey_hash = nacl.hash.sha256(hex_key, encoder=nacl.encoding.HexEncoder)
print("groupkey_hash")
print(groupkey_hash)

groupkey_hash = groupkey_hash.decode('utf-8')
print("post utf 8")
print(type(groupkey_hash))


message_bytes = bytes(login_record + groupkey_hash + target_pubkey + target_username +
    groupkey_encrypted + time_stamp
    , encoding='utf-8')

print("post message bytes addition")

signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
signature_hex_str = signed.signature.decode('utf-8')

print("sigature")
print(signature_hex_str)
print(type(signature_hex_str))


#####3

#create HTTP BASIC authorization header
credentials = ('%s:%s' % (username, password))
b64_credentials = base64.b64encode(credentials.encode('ascii'))
headers = {
    'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
    'Content-Type' : 'application/json; charset=utf-8',
}

payload = {
    "loginserver_record" : login_record,
    "groupkey_hash" : groupkey_hash,
	"target_pubkey" : target_pubkey,
	"target_username" : target_username,
	"encrypted_groupkey" : groupkey_encrypted,
    "sender_created_at" : time_stamp,
    "signature" : signature_hex_str
}
payload = json.dumps(payload).encode('utf-8')

print(payload)

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
