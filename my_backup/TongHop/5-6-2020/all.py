import json
import requests
import shutil
from datetime import *
from python_anticaptcha import *
from keys import ANTICAPTCHA_KEY
import mirror

def anti_Captcha(ANTICAPTCHA_KEY):
	op = open('captcha.png','rb')
	client = AnticaptchaClient(ANTICAPTCHA_KEY)
	task = ImageToTextTask(op)
	job = client.createTask(task)
	job.join()
	text_captcha = job.get_captcha_text()
	return text_captcha
	pass

def get_Captcha(headers,ANTICAPTCHA_KEY):
	print ("Get Captcha")
	url_img = 'http://www.zone-h.org/captcha.py'
	r_img = requests.get(url_img,headers=headers,stream = True)
	with open('captcha.png','wb') as op:
		shutil.copyfileobj(r_img.raw,op)
	text_captcha = anti_Captcha(ANTICAPTCHA_KEY)
	return text_captcha
	pass

def send_Captcha(url,data,headers,ANTICAPTCHA_KEY):
	while (1):
		if 'Copy the code:' in data:
			print ("Captcha")
			text_captcha = get_Captcha(headers,ANTICAPTCHA_KEY)
			print (text_captcha)
			if '<input type="text" name="captcha" value="">' in data:
				captcha = {'captcha':text_captcha}
			else:
				captcha = {'archivecaptcha':text_captcha}
			r = requests.post(url,data=captcha,headers=headers)
			data = r.text
			continue
		elif 'location.href' in data:
			print ("Chuyen huong")
			url = data.split(';')[-2]
			url = url.split('"')[1][:-5]
			r = requests.get(url,headers=headers)
			data = r.text
			continue
		else:
			break
		r = requests.get(url,headers=headers)
		data = r.text
	return data
	pass

def name_Mirror(headers):
	f = open('time.txt','r')
	time = f.read()
	f.close()
	print ("Lay time")
	print (time)
	l =[]
	url = 'http://zone-h.org/archive/page='
	for i in range(1,31):
		url +=str(i)
		r = requests.get(url,headers=headers)
		r.encoding = 'utf-8'
		data = r.text
		data = send_Captcha(url,data,headers,ANTICAPTCHA_KEY)
		temp = data.split("</tr>")
		if len(temp) == 4:
			break
		for i in range(1,len(temp)-4):
			if ((mirror.time_Add(temp[i])) < time):
				break
			else:
				time_add = mirror.time_Add(temp[i])
				print (time_add)

def main():
	headers = {'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',\
				'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36'}
	#cookies = 'ZHE=1eb04b6e42b711aec4a29a007518b2d6;'
	cookies = 'ZHE=f822e7d7c993afb5bf51e16231027658;'
	headers['Cookie'] = cookies
	print ("Hello")
	url = 'http://zone-h.org/archive'
	while (1):
		#r = requests.get(url_archive,headers=headers)
		print ('hello b')
		r = requests.get(url,headers=headers)
		if 'Set-Cookie' in r.headers:
			cookies+=r.headers['Set-Cookie']
			break
		#	PHPSESSID = get_Cookies(r,)
	headers['Cookie'] = cookies
	print(headers)
	
	name_Mirror(headers)
	pass
if __name__ == '__main__':
	main()
