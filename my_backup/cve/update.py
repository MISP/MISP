import mysql.connector
import keys
import pymisp
import cve
import requests
import time





misp= pymisp.ExpandedPyMISP(keys.misp_url, keys.misp_key, False)


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
    
def event_id(d_cve, cursor):
    
    year = d_cve['publish_date'].split('-')[0]
    cursor.execute('select id from events where info="CVE_'+year+'"')
    return cursor.fetchall()[0][0]   


def get_events_id(cursor):
    
    cursor.execute('select id from events where info like "CVE_20%"')
    id=[]
    for i in cursor.fetchall():
        id.append(i[0])
    return id





def obj_id(l_event_id,cursor):
    
    obj =[]
    for i in l_event_id:
      cursor.execute('select object_id from attributes where event_id='+str( i)+' and object_relation ="cvss-score" and  value1 =0.0 and deleted =0 ')
      for j in cursor.fetchall():
        obj.append(j[0])
    return obj
    
def get_data(l_obj_id, cursor):
    
    url ='https://www.tenable.com/cve/'
    kq=[]
    dem=0
    for i in l_obj_id:
        dem=dem+1
        if(dem==60): break
        cursor.execute('select value1 from attributes where object_id= '+str(i)+ ' and object_relation ="id" ')
        name_cve = cursor.fetchall()
        if(len (name_cve)==0): 
          continue
		
        print ("get ",name_cve[0][0])
        r= requests.get(url+name_cve[0][0])
        r.encoding= 'utf-8'
        d={}
        d['obj_id']= i
        d['id']= name_cve[0][0]
        d['description']=cve.description(r)
        d['publish_date']= cve.publish_date(r)
        d['update_date']=cve.update_date(r)
        d['references']=cve.references(r)
        temp = cve.score(r)
        if(len(temp)==0):
            d['score']=''
        else:
            d['score']= temp[len(temp)-1]
        kq.append(d)
    return kq
      
    
    
    
  
    
def update_obj(data, cursor):
    global misp
    for i in data:
      event= event_id(i,cursor)
      misp.delete_object(int(i['obj_id']))
      misp.add_object(event,cve_object(i))

while(1):
  mydb= mysql.connector.connect(host=keys.host, user= keys.user, password= keys.passwd,database= 'misp')
  cursor = mydb.cursor()
  
  	  
  data = get_data(obj_id(get_events_id(cursor),cursor),cursor) 
  update_obj(data, cursor) 
  print(time.strftime("%d-%m-%y, %H-%M: hoan thanh",time.localtime()))
  cursor.close()
  mydb.close()
  time.sleep(12*3600)
	
    

        
    
    






























