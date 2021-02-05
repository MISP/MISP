import socket
import hashlib
import time



port =24002


servers={}
def getPass():
    s={}
    f=open('servers','r')
    temp= (f.read()[:-1]).split('\n')
    f.close()
    for i in temp:
        s[i.split(' ')[0]]=i.split(' ')[1]
    return s
def savePass():
    f=open('servers','w')
    for i in servers.keys():
        f.write(i+' '+servers[i]+'\n')

    f.close()
    

def get_data(ip,pw):
    global servers
    s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((ip,port))
    except:
        return
    print 'connected to ', ip
    
    s.sendall(hashlib.md5(pw).hexdigest())
    data=''
    while(1):
        data=data+s.recv(1024*1024)
        print len(data)
        if(data.find('####')>=0):
            s.sendall('hoan thanh')
            f=open('honey1.log','a')
            f.write(data[:-4])
            f.close()
            dem= int(servers[ip][5:])+1
            servers[ip]= 'Bkav@'+str(dem)
            savePass()
            break


servers= getPass()
while(1):
    for i in servers.keys():
        get_data(i,servers[i])
    time.sleep(30)
    














    


    
