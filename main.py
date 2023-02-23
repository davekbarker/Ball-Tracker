import sqlite3
from app import app

#
# # Create a connection to the database
# conn = sqlite3.connect('my_database.db')
#
# # Create a cursor object
# cur = conn.cursor()
#
# # Create a table
# cur.execute('''CREATE TABLE IF NOT EXISTS my_table
#                (id INTEGER PRIMARY KEY, name TEXT, age INTEGER)''')
#
# # Insert some data
# cur.execute("INSERT INTO my_table (name, age) SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM my_table WHERE name = ?)", ('Alice', 25, 'Alice'))
# cur.execute("INSERT INTO my_table (name, age) SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM my_table WHERE name = ?)", ('Bob', 30, 'Bob'))
#
# # Commit the changes to the database
# conn.commit()
#
# # Retrieve all rows from the table
# cur.execute("SELECT * FROM my_table")
# rows = cur.fetchall()
#
# # Print the results
# for row in rows:
#     print(row)
#
# # Close the connection
# conn.close()


if __name__ == '__main__':
    app.run()