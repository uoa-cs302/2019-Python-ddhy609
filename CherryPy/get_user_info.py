import urllib.request
import json
import base64
import nacl.signing
import nacl.encoding

url = "http://cs302.kiwi.land/api/list_users"

#STUDENT TO UPDATE THESE...
username = "ddhy609"
password = "DevashishDhyani_364084614"



#hex_key = signing_key.encode(encoder=nacl.encoding.HexEncoder)
hex_key = b'c3efb78f4d0bb9bdfbf938aa870ad92298f53e4e0d13b951bcc8f5ac877dc627'
signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)
#print(hex_key)
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

all_users = JSON_object['users']
array_store = []

for x in all_users :
    array_store.append(x['username'])
    if(x['username'] == "fsan110"):
        if(x['status'] == "online"):
            print(x['incoming_pubkey'])
            print("feneel online")
            break

print (array_store)
