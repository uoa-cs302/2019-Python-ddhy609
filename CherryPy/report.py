import urllib.request
import json
import base64
import nacl.signing
import nacl.encoding
 
from subprocess import check_output

url = "http://cs302.kiwi.land/api/report"

#STUDENT TO UPDATE THESE...
username = "ddhy609"
password = "DevashishDhyani_364084614"
status = "online"
#######################################
ip_command = (check_output(["hostname","-I"]))

ip_string = ip_command.decode('utf-8')
ip_string = ip_string[0:len(ip_string)-2]
########################################################

#print(ip)
#ip_add = str(ip)


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
    "connection_address" : "172.23.106.138:10013",   #IP+ListeningPort
	"connection_location" : "1",   #ask if 1 or 0 or if it even matters
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
