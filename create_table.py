import sqlite3


def create_table():
    # Connect to database
    conn = sqlite3.connect('mydatabase.db')

    # Create cursor object
    cursor = conn.cursor()

    # Create table
    cursor.execute('''CREATE TABLE my_table
                    (id INTEGER PRIMARY KEY,
                     name TEXT)''')

    # Save changes and close connection
    conn.commit()
    conn.close()


if __name__ == '__main__':
    create_table()
