from selenium import webdriver
import time
import sys

try:
    browser= webdriver.Firefox(executable_path="./geckodriver")
    browser.get('http://10.2.65.31/users/login')
    browser.maximize_window()

    search = browser.find_element_by_id('UserEmail')
    search.send_keys("admin@admin.test")

    search=browser.find_element_by_id('UserPassword')
    search.send_keys('@Bkav2019.12345a')
    browser.find_element_by_xpath('/html/body/div[11]/div/table/tbody/tr/td[2]/form/button').click()

    f=open('data.txt','rt')
    temp= f.read()[:-1].decode('utf-8')
    f.close()
    if(temp==''):
    	sys.exit('khong co du lieu')


    browser.get('https://10.2.65.31/attributes/add/36')


    element= browser.find_element_by_xpath('//*[@id="AttributeCategory"]')
    element.click()
    browser.find_element_by_xpath('//*[@id="AttributeCategory"]/optgroup/option[16]').click()

    browser.find_element_by_xpath('//*[@id="AttributeType"]').click()
    browser.find_element_by_xpath('//*[@id="AttributeType"]/option[3]').click()
    browser.find_element_by_xpath('//*[@id="id"]/fieldset/div[3]/div[11]/label').click()




    element=browser.find_element_by_xpath('//*[@id="AttributeValue"]')
    element.send_keys(temp)

    time.sleep(2)
    browser.find_element_by_xpath('//*[@id="id"]/button').click()
    browser.close()
except:
    sys.exit('error dua du lieu')


f=open('date.txt','wt')
f.write(temp.split('|')[0]+'~')
f.close()

f=open('data.txt','wt')
f.write('')
f.close()


