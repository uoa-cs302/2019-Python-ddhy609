import urllib.request
import json
import base64
import nacl.signing
import nacl.encoding


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


""" url = "http://cs302.kiwi.land/api/ping"

#STUDENT TO UPDATE THESE...
username = "ddhy609"
password = "DevashishDhyani_364084614"


#hex_key = signing_key.encode(encoder=nacl.encoding.HexEncoder)
private_key = b'c3efb78f4d0bb9bdfbf938aa870ad92298f53e4e0d13b951bcc8f5ac877dc627'
print(private_key)
private_key = nacl.signing.SigningKey(private_key, encoder=nacl.encoding.HexEncoder)

#######


# Sign a message with the signing key

# Obtain the verify key for a given signing key
public_key = private_key.verify_key

pkey = public_key.encode(nacl.encoding.HexEncoder).decode('utf-8')

sign = private_key.sign(bytes(pkey, encoding= 'utf-8'), encoder=nacl.encoding.HexEncoder)

sig = sign.signature.decode('utf-8')

# Serialize the verify key to send it to a third party
#verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)

####copied from hints
#pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
#pubkey_hex_str = pubkey_hex.decode('utf-8')

#message_bytes = bytes(pubkey_hex_str, encoding='utf-8')

#signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
#signature is basically hash. Used to verify pub key is related to private key
#signature_hex_str = signed.signature.decode('utf-8')
####

#create HTTP BASIC authorization header
credentials = ('%s:%s' % (username, password))
b64_credentials = base64.b64encode(credentials.encode('ascii'))
headers = {
    'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
    'Content-Type' : 'application/json; charset=utf-8',
}

payload = {
    "pubkey" : pkey,
	"signature" : sig
}

payload = json.dumps(payload).encode('utf-8')
print(pkey)
print(sig)
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
except:
    print("failed ping")
    #print(error.read())
    #exit()

JSON_object = json.loads(data.decode(encoding))
print(JSON_object)
 """