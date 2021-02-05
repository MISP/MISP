from python_anticaptcha import AnticaptchaClient, ImageToTextTask
from selenium import webdriver
from pyvirtualdisplay import Display
from PIL import Image
import time
import io
import sys
import os
 
api_key ="31c898bcef129ea7c65321645d967e31"



def antiCaptcha(captcha_fp):
    client = AnticaptchaClient(api_key)
    task = ImageToTextTask(captcha_fp)
    job = client.createTask(task)
    job.join()
    x=job.get_captcha_text()
    return x

def xuLyCaptcha(element,browser):
    location = element.location
    size = element.size
    browser.save_screenshot('a.png')

    im=Image.open('a.png')
    left= location['x']
    right=left+size['width']
    top= location['y']
    bottom=top+size['height']
    im=im.crop((left,top,right,bottom))
    im.save('captcha.png')

    f=open('captcha.png','rb')
    s=antiCaptcha(f)
    
    print s
    
    f.close()
    try:
        element=browser.find_element_by_name('captcha')
    except:
        element=browser.find_element_by_name('archivecaptcha')
    element.send_keys(s)
	
    browser.find_element_by_xpath('/html/body/div/div[3]/div/form/input[@type="submit"]').click()




   
    

def Get(url):
    browser.get(url)
    while(1):
        try:
            element=browser.find_element_by_xpath('//*[@id="cryptogram"]') #captcha
        except:
            try:
                element=browser.find_element_by_xpath('/html/body/center[1]/h1')
                browser.get(url)
                continue
            except:
                print 'a'
            return
        xuLyCaptcha(element,browser)

"""
def getInfo(url):
    temp=''
    Get(url)
    element=browser.find_element_by_xpath('//*[@id="propdeface"]/ul/li[1]') #ngay thang
    temp=temp+element.text+'\n'
    temp=temp+browser.find_element_by_xpath('//*[@id="propdeface"]/ul/li[2]/ul/li[1]').text+'\n'
    temp=temp+browser.find_element_by_xpath('//*[@id="propdeface"]/ul/li[2]/ul/li[2]').text+'\n'
    temp=temp+browser.find_element_by_xpath('//*[@id="propdeface"]/ul/li[2]/ul/li[3]').text+'\n'
    temp=temp+browser.find_element_by_xpath('//*[@id="propdeface"]/ul/li[3]/ul/li[1]').text+'\n'
    temp=temp+browser.find_element_by_xpath('//*[@id="propdeface"]/ul/li[3]/ul/li[2]').text
    print temp
    return temp
"""


def getInfo(url,date):
    Get(url)
    info=''
    end =False
    for i in range(2,27):
        temp=''
        element= browser.find_element_by_xpath('//*[@id="ldeface"]/tbody/tr['+str(i)+']/td[1]')
        temp= element.text+'|'
        temp= temp+browser.find_element_by_xpath('//*[@id="ldeface"]/tbody/tr['+str(i)+']/td[2]/a').text+'|'
        temp= temp+browser.find_element_by_xpath('//*[@id="ldeface"]/tbody/tr['+str(i)+']/td[8]').text+'|'
        temp= temp+browser.find_element_by_xpath('//*[@id="ldeface"]/tbody/tr['+str(i)+']/td[9]').text
        if(temp<date):
            end=True
            break
        info= info+temp+'\n'
	print info
    temp =raw_input()
    return [end,info] 
       

    
try:
	browser= webdriver.Firefox(executable_path="./geckodriver")
	kq=''
	f= open('date.txt','r')
	date = f.readline()
	f.close()
	    
	for i in range(50):
		url='http://www.zone-h.org/archive/filter=1/domain=.vn/fulltext=1/page='+str(i+1)
		temp =getInfo(url,date)
		kq= kq +temp[1]
		if(temp[0]==True):
			print kq
			break
except:
	sys.exit('error get_data')



f=open('data.txt','a')
f.write(kq.encode('utf-8'))
f.close()
browser.close()
#os.system('python duadulieu.py')







    











