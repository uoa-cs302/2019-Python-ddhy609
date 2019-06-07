import urllib.request
import json
import base64
import nacl.signing
import nacl.encoding
import time


#cs302.kiwi.land needs to be replaced by IP address+ListeningPort of receiver
IP= "172.23.114.169:1234"
ip_rshi = "172.23.103.37:1234"
url = "http://"+ IP +"/api/rx_broadcast"

#STUDENT TO UPDATE THESE...
username = "ddhy609"
password = "DevashishDhyani_364084614"


#space after emoji required to allow for overlap b/w emoji and text
message = "\U0001F637 " + "Checking against APi doc NEW"
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
server_time= str(time.time())
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
