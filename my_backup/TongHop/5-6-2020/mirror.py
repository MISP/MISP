import requests
import json

def time_Add(x):
	tmp = x.find('<td>')+len('<td>')
	time_add = x[tmp:x.find('</td>')]
	return time_add