import requests
import json



def description(r):
    temp = r.text[r.text.find('description" content="')+len('description" content="'):]
    temp= temp[:temp.find('"')]
    temp= temp.replace('&quot;','"')
    temp= temp.replace('&#039;',"'")
    temp= temp.replace('&#x27;',"'")
    return temp.strip()

def publish_date(r):
    temp= r.text[r.text.find('Published<!'):]
    temp = temp.split('span>')[1]
    temp= temp[:-2]
    return temp.strip()
def update_date(r):
    temp= r.text[r.text.find('<strong>Updated'):]
    temp=temp.split('span>')[1]
    temp= temp[:-2]
    return temp.strip()
def references(r):
    temp = r.text[r.text.find('<h3>References<'):]
    temp= temp[: temp.find('class')]
    temp = temp.split('href="')
    l=[]
    for i in range(1,len(temp)):
        l.append(temp[i].split('"')[0])
    return l
def score(r): #return score[2.0, 3.0]
    l=[]
    i = r.text.find('<strong>Base Score')
    if(i==-1):
        return l
    temp= r.text[i:]
    l.append(temp.split('span>')[1][:-2])
    temp = temp[5:]
    i = temp.find('<strong>Base Score')
    if(i!=-1):
        temp= temp[i:]
        l.append(temp.split('span>')[1][:-2])
    return l
    





               

