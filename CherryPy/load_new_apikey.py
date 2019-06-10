import urllib.request
import json
import base64
import nacl.signing
import nacl.encoding
import time
import server
###
#Get the login server record not authorised at the moment 
##
url = "http://cs302.kiwi.land/api/load_new_apikey"
#create request and open it into a response object
username = "ddhy609"
password = "DevashishDhyani_364084614"


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
print(JSON_object)