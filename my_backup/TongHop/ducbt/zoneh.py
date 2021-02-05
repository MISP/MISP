import requests
import shutil
from python_anticaptcha import *
import time
import pymisp



ANTICAPTCHA_KEY ="31c898bcef129ea7c65321645d967e31"
#url_index = "http://www.zone-h.org/"
url_index = "http://www.zone-h.org/archive/filter=1/domain=.vn/fulltext=1/page=1"

def Get_Cookies(url_index, headers, cookies):
	#while (1):
	r = requests.get(url_index,headers=headers,cookies=cookies)
	r.encoding = 'utf-8'
	url = r.url
	"""
	if fail not in r.text:
		continue
	break"""
	PHPSESSID = (r.headers['Set-Cookie'].split('=')[1])
	PHPSESSID = PHPSESSID.split(';')[0]
	cookies['PHPSESSID'] = PHPSESSID
	#data = r.text
	#url_zoneh = r.url
	return cookies, url

def Get_Captcha(headers,cookies):
	#data = {'searchinput':'.vn'}
	url_img = 'http://www.zone-h.org/captcha.py'
	r_img = requests.get(url_img,headers= headers,cookies=cookies,stream = True)
	with open("captcha.png", "wb") as op:
		shutil.copyfileobj(r_img.raw, op) 
	text_captcha = Anti_Captcha(ANTICAPTCHA_KEY)
	#print (text_captcha)	
	#response = r.text
	#return response
	return text_captcha

def Anti_Captcha(ANTICAPTCHA_KEY):
	captcha_png = open("captcha.png","rb")
	client = AnticaptchaClient(ANTICAPTCHA_KEY)
	task = ImageToTextTask(captcha_png)
	job = client.createTask(task)
	job.join()
	print ("Dang xu li captcha...!")
	text_captcha = job.get_captcha_text()
	print (text_captcha)
	return text_captcha

#def Captcha_Hanlding(url,headers,cookies):
def Get_Data_Day(url,headers,cookies):
	#data = {'filter_date_select':'today'}
	data = {'notifier':'','domain':'.vn','fulltext':'on','filter_date_select':'today','filter':1}
	r = requests.post(url,headers=headers,cookies=cookies,data=data)
	data = r.text
	#print (data)
	return data

	
def Send_Captcha(url,headers,cookies):
	
	while (1):
		r = requests.get(url,headers=headers,cookies=cookies)
		data = r.text
		"""
		if 'Copy the code' in data:
			for line in data:
				if 'submit' in line:
					print (line)
					break
		"""
		try:
			if 'Copy the code' in data:
				print ("Copy code in data!!!!!!!")
				text_captcha = Get_Captcha(headers,cookies)
				if '<input type="text" name="captcha" value=""><input type="submit">' in data:
					captcha = {'captcha':text_captcha}
				else:
					captcha = {'archivecaptcha':text_captcha}
				r = requests.post(url,data = captcha, headers=headers,cookies=cookies)
				data = r.text
				#print (data)
				#print (data)
				#sleep(20)
				#print (data)
				continue
			elif 'location.href' in data:
				print ("Chuyen huong data !!!!!!!")
				url = data.split(';')[-2]
				#'location.href="http://www.zone-h.org/archive/filter=1/domain=.vn/fulltext=1/page=1?hz=1"'
				url = url.split('"')[1][:-5]
				#print (url)
				#http://www.zone-h.org/archive/filter=1/domain=.vn/fulltext=1/page=1?hz=1
				r = requests.get(url,headers=headers,cookies=cookies)
				text_captcha = Get_Captcha(headers,cookies)
				captcha = {'archivecaptcha':text_captcha}
				r = requests.post(url,data = captcha, headers=headers,cookies=cookies)
				data = r.text
				#print (data)
				#sleep(20)
				#data = r.text
				continue
			elif data == None: 
				
				text_captcha = Get_Captcha(headers,cookies)
				captcha = {'archivecaptcha':text_captcha}
				r = requests.post(url,data = captcha, headers=headers,cookies=cookies)
				data = r.text
				
				continue
			else:
				#print (r.headers)
				data = Get_Data_Day(url,headers,cookies)
				break
		except:
			continue		
		pass
	return data

"""
def get_Mirror(headers,cookies):
	fp = open("datapage.txt","r")
	list_url = []
	for line in fp:
		url_index = url = 'http://zone-h.org'

		if 'href="/mirror/id/' in line:
			#print (line)
			line = line.split('"')[1]
			url_index +=line
			list_url.append(url_index)
		else:
			break
	return list_url
	pass
def get_Data_Mirror(list_url,headers,cookies):
	if list_url = '[]':
		break
	else:
		for url in list_url:
			r = requests.get(url,headers=headers,cookies= cookies)
			data_mirror = r.text
	list_mirror = []
	mirror = {}
	return data_mirror

def send_Mirror_to_MISP():
"""


def main():

	headers = {
	'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.92 Safari/537.36',
	'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
	}
	#cookies = {'ZHE':'070221fdf474b12e4917dfaa90eecd5d'}
	#cookies = {'ZHE':'6419b9f6abd2f35a63022ff997c50691'}
	cookies = {'ZHE':'f822e7d7c993afb5bf51e16231027658'}
	while (1):
		#ping_url
		try:
			cookies,url = Get_Cookies(url_index,headers,cookies)
			break
		except:
			continue
	
	while (1):
		try:
			data = Send_Captcha(url,headers,cookies)
			fp = open("datapage.txt","wb")
			fp.write(data)
			fp.close()
			break
		except:
			continue
		pass
	break
	
	#print (cookies)
	#print (data)
if __name__ == '__main__':
	main()
	sleep(3600)



