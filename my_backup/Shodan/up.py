import pymisp
import json

misp_url = "https://10.2.65.31/"
misp_key = "7SYHNZovnNz9o8hgnjOOcPt36KvrEmXK1ajINifd"

misp= pymisp.ExpandedPyMISP(misp_url, misp_key, False)

f = open("shodan_data.json","r")
for line in f:
	data = json.loads(line)
	
    	#obj.add_attribute("ip",data['ip_str'])
    	#obj.add_attribute("port",data['port'])
    	#obj.add_attribute("org",data['org'])
    	#obj.add_attribute("text",data['product'])
	#misp.add_object("5",obj)
	ip = data["ip_str"]
	port = data["port"]
	org = data["org"]
	product = data["product"]
	
	obj = pymisp.MISPObject('shodan-report')
	obj.add_attribute("ip",ip)
	obj.add_attribute("port",port)
	obj.add_attribute("org",org)
	obj.add_attribute("text",product)
	misp.add_object("74",obj)

	

f.close()
