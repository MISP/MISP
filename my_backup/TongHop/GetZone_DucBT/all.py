import json
import requests
import shutil
import datetime
from python_anticaptcha import *
from keys import ANTICAPTCHA_KEY#,cookies
import mirror
import time

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
			time.sleep(3)
			url = data.split(';')[-2]
			url = url.split('"')[1][:-5]
			r = requests.get(url,headers=headers)
			data = r.text
			continue
		else:
			break
		#r = requests.get(url,headers=headers)
		#data = r.text
	return data
	pass

def name_Mirror(headers,last_day):
	utcnow = datetime.datetime.utcnow()
	utcnow = utcnow.strftime("%Y-%m-%d")
	#Check ngay UTC time.
	if utcnow > last_day:
		f_time = open('time.txt','w+')
		f_time.write('00:00')
		f_time.close()

		f_ld = open('last_day.txt','w+')
		f_ld.write(utcnow)
		f_ld.close()

	f = open('time.txt','r')
	time = f.read()
	f.close()
	print ("Lay time")
	print (time)
	list_url =[]
	
	for i in range(1,31):
		print('Page ', i)
		url = 'http://zone-h.org/archive/page='
		url +=str(i)
		print(url)
		r = requests.get(url,headers=headers)
		r.encoding = 'utf-8'
		data = r.text
		data = send_Captcha(url,data,headers,ANTICAPTCHA_KEY)
		temp = data.split("</tr>")
		print (len(temp))
		if len(temp) == 4:
			return list_url
		for j in range(1,(len(temp)-4)):
			if i == 1 and j == 1:
				last_time = mirror.time_Add(temp[1])
				print("Last time: " + last_time)
				f = open('time.txt','w+')
				f.write(last_time)
				f.close()
			if ((mirror.time_Add(temp[j])) <= time):
				return list_url
			else:
				#time_add = mirror.time_Add(temp[i])
				#print (time_add)
				print ('Miror ',j)
				list_url.append(mirror.link_Mirror(temp[j]))
	#print (l)
	return list_url
	pass

def get_Data_Mirror(headers,last_day):
	list_url = name_Mirror(headers,last_day)
	list_mirror = []
	check = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">'
	for url_mirror in list_url:
		data_mirror = {}
		r = requests.get(url_mirror,headers=headers)
		data = r.text
		if 'Copy the code:' in data:
			print('Copy the code...')
			text_captcha = get_Captcha(headers,ANTICAPTCHA_KEY)
			if '<input type="text" name="captcha" value=""><input type="submit">' in data:
				captcha = {'captcha':text_captcha}
			else:
				captcha = {'archivecaptcha':text_captcha}
			r=requests.post(url_mirror,data=captcha,headers=headers)
			data = r.text
			fo = open('data.txt','w+')
			fo.write(data)
			fo.close()
			data_mirror = mirror.handling_Mirror(data_mirror)
			#print (data_mirror)
			list_mirror.append(data_mirror)
		elif check in data :
			fo2 = open('data.txt','w+')
			fo2.write(data)
			fo2.close()
			data_mirror = mirror.handling_Mirror(data_mirror)
			#print (data_mirror)
			list_mirror.append(data_mirror)
		else:
			print('Khong co du lieu moi..')
			continue
	#print(list_mirror)
	return list_mirror

def main():
	headers = {'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',\
				'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0'}
	#cookies = 'ZHE=1eb04b6e42b711aec4a29a007518b2d6;'
	#PHPSESSID=0dg4q8slvp7tripisd8ccupob0;'
	cookies = 'ZHE=719647b041fd58da0413fe9fffad2236;'
	headers['Cookie'] = cookies
	print ("Hello")
	url = 'http://zone-h.org/archive'
	while (1):
		#r = requests.get(url_archive,headers=headers)
		r = requests.get(url,headers=headers)
		print(r.text)
		if 'location.href' in r.text:
			time.sleep(3)
			print ("Chuyen huong")
			url = r.text.split(';')[-2]
			url = url.split('"')[1][:-5]
			print (url)
			r = requests.get(url,headers=headers)
			#data = r.text
		if 'Set-Cookie' in r.headers:
			cookies+=r.headers['Set-Cookie']
			break
		#	PHPSESSID = get_Cookies(r,)
	headers['Cookie'] = cookies
	print(headers)
	while (1):
		f_ld = open('last_day.txt','r')
		last_day = f_ld.read()
		f_ld.close()
		data =get_Data_Mirror(headers,last_day)
		data = str(data)
		print(data)  
		time_string = time.strftime("%d_%m_%Y",time.localtime())
		f = open('Ngay_'+time_string+'.txt','a')
		f.write(data)
		f.close()
		
		time_string = time.strftime("%m_%Y",time.localtime())
		f = open('Thang_'+time_string+'.txt','a')
		f.write(data)
		f.close()
		
		#time.sleep(2300) 
		print('60 phut...')
		time.sleep(300)
		#break
	pass

if __name__ == '__main__':
	main()
