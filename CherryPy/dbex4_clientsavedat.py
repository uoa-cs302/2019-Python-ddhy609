import sqlite3

#create my.db if it does not exist, if exists just connects to it
conn = sqlite3.connect("my.db")
#to interact with db get the cursor
c=conn.cursor()


c.execute("""
            create table trial_objects (id integer primary key autoincrement not null,         
            created_at float not null)
         """
            )
            
conn.commit()            


#close db
conn.close