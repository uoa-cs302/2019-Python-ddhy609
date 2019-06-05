import urllib.request
import json
import base64
import nacl.signing
import nacl.encoding
import time

##need to update later to allow for user to user messaging. Atm, just hammonds client.
url = "http://172.23.114.169:1234/api/rx_privatemessage"   #rx_privatemessage"



#STUDENT TO UPDATE THESE...
#oberoi pubkey = d76697455341f10649c6ac6241db51c3cc5a2bb9212384b0b3b21bddca1f6a87
#feneel pubkey = 78123e33622eb039e8c20fb30713902c37bf9fe4493bd1e16e69cd8cc129e03e
target_pubkey = "78123e33622eb039e8c20fb30713902c37bf9fe4493bd1e16e69cd8cc129e03e"
target_username = "fsan110"
username = "ddhy609"
password = "DevashishDhyani_364084614"

message = bytes("Decryption! \U0001F637  !!!!", encoding='utf-8')
# Generate a new random signing key
hex_key = b'c3efb78f4d0bb9bdfbf938aa870ad92298f53e4e0d13b951bcc8f5ac877dc627'
signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)

time_stamp = str(time.time())

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
	"target_pubkey" : target_pubkey,
	"target_username" : target_username,
	"encrypted_message" : message_encrypted,
    "sender_created_at" : time_stamp,
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
