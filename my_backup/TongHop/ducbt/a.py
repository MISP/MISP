import requests
import shutil
from python_anticaptcha import *



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
	print ("Dang xu li captcha...")
	text_captcha = job.get_captcha_text()
	print (text_captcha)
	return text_captcha

#def Captcha_Hanlding(url,headers,cookies):
def Get_Data_Day(url,headers,cookies):
	data = {'domain':'.vn','notifier':'','filter': 1, 'fulltext': 'on','filter_date_select':'today'}
	r = requests.get(url,headers=headers,cookies=cookies)
	data = r.text
	print (data)
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
				text_captcha = Get_Captcha(headers,cookies)
				captcha = {'archivecaptcha':text_captcha}
				r = requests.post(url,data = captcha, headers=headers,cookies=cookies)
				data = r.text
				#print (data)
				print ("______NHAN_THE_KHO_DAU________________________")
				#print (data)
				continue
			elif 'location.href' in data:
				print ("Chuyen huong")
				url = data.split(';')[-2]
				#'location.href="http://www.zone-h.org/archive/filter=1/domain=.vn/fulltext=1/page=1?hz=1"'
				url = url.split('"')[1][:-5]
				print (url)
				#http://www.zone-h.org/archive/filter=1/domain=.vn/fulltext=1/page=1?hz=1
				r = requests.get(url,headers=headers,cookies=cookies)
				text_captcha = Get_Captcha(headers,cookies)
				captcha = {'archivecaptcha':text_captcha}
				r = requests.post(url,data = captcha, headers=headers,cookies=cookies)
				data = r.text
				#data = r.text
				continue
			else:
				break
		except:
			continue
		
		pass
	
	return data


def main():

	headers = {
	'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.92 Safari/537.36',
	'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
	}
	cookies = {'ZHE':'070221fdf474b12e4917dfaa90eecd5d'}
	
	while (1):
		try:
			cookies,url = Get_Cookies(url_index,headers,cookies)
			break
		except:
			continue
	data = Send_Captcha(url,headers,cookies)
	print (data)
	#print ("===========================================================================")
	#print(data)
	



if __name__ == '__main__':
	main()

