import pymisp

misp_url = "https://10.2.65.31/"
misp_key = "7SYHNZovnNz9o8hgnjOOcPt36KvrEmXK1ajINifd"
misp= pymisp.ExpandedPyMISP(misp_url, misp_key, False)
event = misp.get("1289")

ccBIF=[]
domain = []
f = open("blacklist.sql","r")
for i in f:
	if "INSERT INTO `blacklistcandcserver` VALUES" in i:
		data=i
data = data.split(",")
data.remove(data[0])
for i in range(0,len(data),3):
	ccBIF.append(data[i].replace("'",""))


for i in ccBIF:
	check=i.replace(".","")
	if check.isdigit():
		event.add_attribute(type='ip-dst', value=i)
		continue
	else:
		event.add_attribute(type='domain',value=i)

misp.update_event(event)
f.close()