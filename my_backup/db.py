import mysql.connector
import time
mydb = mysql.connector.connect(host='localhost',user='hai',passwd='Bkav@2019', database='misp')
mycursor = mydb.cursor()

s= time.time()



mycursor.execute("SELECT value1 FROM attributes where value1 like '%CVE%' limit 100")




myresult = mycursor.fetchall()
print time.time()-s
print type(myresult)
print (myresult)