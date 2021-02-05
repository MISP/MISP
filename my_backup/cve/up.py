import pymisp
import keys
import json
import mysql.connector


mydb = mysql.connector.connect(host=keys.host,user= keys.user,passwd=keys.passwd,database='misp')

cursor =mydb.cursor()



def cve_object(d_cve):
    obj = pymisp.MISPObject('vulnerability')
    obj.add_attribute('id',value= d_cve['id'])
    obj.add_attribute('cvss-score',value=d_cve['score'])
    obj.add_attribute('published',value=d_cve['publish_date'])
    obj.add_attribute('modified',value=d_cve['update_date'])
    
    obj.add_attribute('description',value=d_cve['description'])
    for i in d_cve['references']:
        obj.add_attribute('references',value=i)
    
    return obj

def event_id(d_cve):
    global cursor
    year = d_cve['publish_date'].split('-')[0]
    #print('select id from events where info="CVE_'+year+'"')
    cursor.execute('select id from events where info="CVE_'+year+'"')
    return cursor.fetchall()[0][0]
   

def check(d_cve): 
    global cursor
    
    cursor.execute('select * from attributes where event_id= '+str(event_id(d_cve))+ ' and deleted = 0 and value1= "' +d_cve['id']+'"')
    data=cursor.fetchall()
    if(len(data)==0):
        return False
    return True
    
      


f=open('data.txt','r')
l= json.loads(f.read())
f.close()



misp= pymisp.ExpandedPyMISP(keys.misp_url, keys.misp_key, False)


for i in l:
    if(check(i)):
        continue
    misp.add_object(event_id(i),cve_object(i))
    print (i['id'])

f=open("date.txt","w")
f.write(l[0]['publish_date'])
f.close()

cursor.close()
mydb.close()


    







