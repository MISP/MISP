import requests


#r = requests.get('http://zone-h.org/archive')
print ("Done")
r = requests.get('https://facebook.com')
print (r.status_code)
