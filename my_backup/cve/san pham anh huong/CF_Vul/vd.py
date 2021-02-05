import pymisp
import keys
import json


def cve_object(id, l):
    obj = pymisp.MISPObject('vulnerability')
    obj.add_attribute('id',value= id)
    
    for i in l:
        obj.add_attribute('vulnerable_configuration',value=i)
    
    return obj





1305
misp= pymisp.ExpandedPyMISP(keys.misp_url, keys.misp_key, False)


f=open('CVE_edit_2011.txt','r')
data = json.loads(f.read())
f.close()


dem=0 
#3620
for i in data.keys():
 dem= dem+1
 print (dem,'. ',i)
 misp.add_object(1313,cve_object(i,data[i]))
 
print ("Done!")

