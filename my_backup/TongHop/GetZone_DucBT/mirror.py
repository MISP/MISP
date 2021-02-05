import requests
import json

def time_Add(x):
	tmp = x.find('<td>')+len('<td>')
	time_add = x[tmp:x.find('</td>')]
	return time_add
def link_Mirror(x):
	url_mirror = 'http://zone-h.org'
	tmp = x.find('/mirror/id')
	mirror = x[tmp:x.find('">mirror')]
	url_mirror+=mirror
	return url_mirror
def handling_Mirror(data_mirror):
    fo = open('data.txt','r')
    for line in fo:
        #data_mirror = {'mirror saved on':'', 'notified by':'','domain':'','ip address':'','system':'','web server':'','link':''}
        if 'Mirror saved on' in line:
            #<li class="deface0"><strong>Mirror saved on:</strong> 2020-04-19 17:19:21</li>
            i = line.find("Mirror saved on:</strong> ") + len("Mirror saved on:</strong> ")
            data_mirror['mirror saved on'] = line[i:-6]
            #print ("1"+line[i:-6])
        elif 'class="defacef"><strong>Notified by:</strong> ' in line:
            i = line.find('class="defacef"><strong>Notified by:</strong> ') + len('class="defacef"><strong>Notified by:</strong> ')
            data_mirror['notified by'] = line[i:-6]
            #print ("2"+line[i:-6])
        elif 'class="defaces"><strong>Domain:</strong>' in line:
            i = line.find("Domain:</strong> ") + len("Domain:</strong> ")
            data_mirror['domain'] = line[i:-6]
            #print ("3"+line[i:-6])
        elif 'IP address:</strong> ' in line:
            i = line.find("IP address:</strong> ") + len("IP address:</strong> ")
            j = line.find('  <img src="')
            data_mirror['ip address'] = line[i:j]
            #print ("4"+line[i:j])
            line = line.split('"')
            country = line[-2]
            data_mirror['country'] = country
        elif 'System:</strong> ' in line:
            i = line.find("System:</strong> ") + len("System:</strong> ")
            data_mirror['system'] = line[i:-6]
            #print ("5"+line[i:-6])
        elif 'Web server:</strong> ' in line:
            i = line.find("Web server:</strong> ") + len("Web server:</strong> ")
            data_mirror['web server'] = line[i:-6]
            #print ("6"+line[i:-6])
        elif '" width="100%"' in line:
            i = line.find('" width="100%"')
            data_mirror['link'] = line[1:i]
            #print ("7"+line[1:i])
        else:
            continue
    fo.close()
    #print (data_mirror)
    return data_mirror
