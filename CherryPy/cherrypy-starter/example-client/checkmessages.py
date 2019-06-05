import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing

Time =1558765969.000000
#STUDENT TO UPDATE THESE...
username = "fsan110"
password = "fsan110_586762257"
private_key =b'747c96a47d361798c8bfc0e3fd7327260fd3d926a9d6020cd173681ad3601d42'
private_key=nacl.signing.SigningKey(private_key, encoder=nacl.encoding.HexEncoder)
#public key
public_key=private_key.verify_key
#changing key to string
pkey=public_key.encode(nacl.encoding.HexEncoder).decode('utf-8')
#generated a signature by signing the message (addded pkey+username in bytes then reconvert to hex)
sign = private_key.sign(bytes(pkey,encoding='utf-8'), encoder=nacl.encoding.HexEncoder)
#create a string signature
sig = sign.signature.decode('utf-8')
#create HTTP BASIC authorization header
credentials = ('%s:%s' % (username, password))
b64_credentials = base64.b64encode(credentials.encode('ascii'))

#url = "http://cs302.kiwi.land/api/checkmessages?since="+(Time)
#kazuki 172.23.46.106:1234
#feneel 172.23.114.169
url= "http://172.23.114.169:1234/api/checkmessages?since="+str(Time) #dev


headers = {
    'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
    'Content-Type' : 'application/json; charset=utf-8',
}
payload ={
    ##GET REQUEST NO PAYLOAD
}

A=json.dumps(payload).encode('utf-8')

req = urllib.request.Request(url,data=A,headers=headers)
response = urllib.request.urlopen(req)

data = response.read() # read the received bytes
encoding = response.info().get_content_charset('utf-8')


JSON_object = json.loads(data.decode(encoding))
#print(JSON_object)

broadcast_data = JSON_object['broadcasts']
message_data = JSON_object['private_messages']

print(broadcast_data)
response.close()