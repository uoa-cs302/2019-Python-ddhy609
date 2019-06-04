import sqlite3

#create my.db if it does not exist, if exists just connects to it
conn = sqlite3.connect("my.db")
#to interact with db get the cursor
c=conn.cursor()


username = "hammond"
password = "awesome"
#created_at is a real number does not return anything if it is 0
#DO NOT DO SELECT* as it selects all the data bad practice
# SQL INJECTION HANDLED by passing in username and password and using ?? 
c.execute("""
           SELECT 
           username,password,created_at from users WHERE username=? and password=?  
          """,(username,password)
            )
            

rows=c.fetchall()
for row in rows:       
    print(row)

#close db
conn.close