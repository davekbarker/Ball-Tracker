import sqlite3

conn = sqlite3.connect('clubs.db')
c = conn.cursor()

# Create table
c.execute('''CREATE TABLE golf_clubs
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              direction INTEGER NOT NULL,
              hits INTEGER NOT NULL,
              distance INTEGER NOT NULL)''')

# Insert sample data for each club
clubs = [('Driver', 0, 0, 0),
         ('3 Wood', 0, 0, 0),
         ('5 Wood', 0, 0, 0),
         ('4 Hybrid', 0, 0, 0),
         ('6 Iron', 0, 0, 0),
         ('7 Iron', 0, 0, 0),
         ('8 Iron', 0, 0, 0),
         ('9 Iron', 0, 0, 0),
         ('P Wedge', 0, 0, 0),
         ('52 Wedge', 0, 0, 0),
         ('56 Wedge', 0, 0, 0),
         ('60 Wedge', 0, 0, 0),
         ('64 Wedge', 0, 0, 0),
         ('Putter', 0, 0, 0)]

c.executemany('INSERT INTO golf_clubs (name, direction, hits, distance) VALUES (?, ?, ?, ?)', clubs)

# Save the changes
conn.commit()

# Close the connection
conn.close()
