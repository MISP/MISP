from pymisp.tools import GenericObjectGenerator
import pymisp
import keys
import json


def zone():
	zone = []
	for i in range(1,6):
		#if i in [15,25,30,32,40]:
		#	continue
		try:
			#f = open('page'+str(i)+'.txt','r',encoding='utf-8')
			f = open('Thang_5_Page_'+str(i)+'.txt','r',encoding='utf-8')
			data = f.read()
			data = data.replace("'",'"')
			z = json.loads(data)
			f.close()
			for mirror in z:
				zone.append(mirror)
		except:
			continue
	return zone

misp_url = "https://10.2.65.31/"
misp_key = "7SYHNZovnNz9o8hgnjOOcPt36KvrEmXK1ajINifd"
def main():
	data_json = zone()
	#print (data_json)
	#tmp = 0
	misp= pymisp.ExpandedPyMISP(misp_url, misp_key, False)
	event= pymisp.MISPEvent()
	event.info= 'Web_Attacked_2'
	
	print (len(data_json))
	dem = 0
	for mirror in data_json:
		try:
			mirror_saved_on = {'mirror saved on':{'value':mirror['mirror saved on'],'type':'datetime'}}
			notified_by = {'notified by':{'value':mirror['notified by'],'type':'text'}}
			domain = {'domain':{'value':mirror['domain'],'type':'link'}}
			system = {'system':{'value':mirror['system'],'type':'text'}}
			ip_address = {'ip address':{'value':mirror['ip address'],'type':'ip-dst'}}
			web_server = {'web server':{'value':mirror['web server'],'type':'text'}}
			link = {'link mirror':{'value':mirror['link'],'type':'link'}}
			country = {'country':{'value':mirror['country'],'type':'text'}}
			#attributeAsDict =[mirror_saved_on,notified_by,domain,system,ip_address,web_server,link]
			attributeAsDict =[mirror_saved_on,notified_by,domain,system,ip_address,web_server,link,country]
			misp_object = GenericObjectGenerator('zoneh-report')
			misp_object.generate_attributes(attributeAsDict)
			event.add_object(misp_object)
			#print (dem)
		except:
			print(dem)
			continue
	misp.add_event(event)


	"""for mirror in data_json:
		mirror['mirror saved on']
		#tmp+=1
		
		mirror_saved_on = {'mirror saved on':{'value':mirror['mirror saved on'],'type':'datetime'}}
		notified_by = {'notified by':{'value':mirror['notified by'],'type':'ip-dst'}}
		domain = {'domain':{'value':mirror['domain'],'type':'domain'}}
		system = {'system':{'value':mirror['system'],'type':'text'}}
		ip_address = {'ip address':{'value':mirror['ip address'],'type':'text'}}
		web_server = {'web server':{'value':mirror['web server'],'type':'text'}}
		link = {'link mirror':{'value':mirror['link'],'type':'text'}}

		attributeAsDict =[mirror_saved_on,notified_by,domain,system,ip_address,web_server,link]
		misp_object = GenericObjectGenerator('my-cool-template')
		misp_object.generate_attributes(attributeAsDict)

		event.add_object(misp_object)
	misp.add_event(event)
	"""
	pass

if __name__ == '__main__':
 	main()
 	print ("Done....")
