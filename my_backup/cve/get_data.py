import cve
import requests
import json
import time
import os




def name_cve(date):
    l=[]
    url= 'https://www.tenable.com/cve/newest?page='
    for i in range(200):
        r= requests.get(url+str(i+1))
        r.encoding= 'utf-8'
        temp = r.text.split('href="/cve/CVE-')
        
        for i in range(1,len(temp)):
            l.append('CVE-' + temp[i].split('"')[0])
        r= requests.get('https://www.tenable.com/cve/'+l[len(l)-1])
        r.encoding='utf-8'
        print (cve.publish_date(r))
        if(cve.publish_date(r)<date):
            break
    
    return l

def save(l_cve):
    f=open('data.txt','w')
    f.write(json.dumps(l_cve))
    f.close()


def get_data(l_name):
    url ='https://www.tenable.com/cve/'
    kq=[]
    f=open('data.txt','r')
    data= f.read()
    if(len(data)!=0):
        kq= json.loads(data)
    f.close()
    
    length= len(l_name)
    for i in range(length):
        if(data.find('"'+l_name[i]+'"')!= -1):
            continue

        
        r= requests.get(url+l_name[i])
        r.encoding= 'utf-8'
        d={}
        d['id']= l_name[i]
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
        print(i,' ',l_name[i])
        if(i%200==199):
            save(kq)
        
    
        
    f=open('data.txt','w')
    f.write(json.dumps(kq))
    f.close()


while(1):
	f=open('date.txt','r')
	date= f.read()
	f.close()


	l=name_cve(date)

	get_data(l)

	if(os.system('python3 up.py')!=0):
        	print('error')
        	break
     
	f=open('data.txt','w')
	f.write("")
	f.close()
	print(time.strftime("%d-%m-%y, %H-%M: hoan thanh",time.localtime()))
	time.sleep(10*3600)
	
   











