import sqlite3

#create my.db if it does not exist, if exists just connects to it
conn = sqlite3.connect("messages.db")
#to interact with db get the cursor
c=conn.cursor()


c.execute("""
            create table messages (id integer primary key autoincrement not null,
            username text not null,
            message text,
            time_at text not null)
         """
            )
            

conn.commit()            


#close db
conn.close