import urllib.request
import json
import base64
import nacl.utils
import nacl.secret
import nacl.signing
import nacl.encoding
import nacl.pwhash

url = "http://cs302.kiwi.land/api/get_privatedata"

#STUDENT TO UPDATE THESE...
username = "ddhy609"
password = "DevashishDhyani_364084614"
uniquepass = "password"
#print (signature_hex_str)

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