import sqlite3

connection = sqlite3.connect('practice.db')
c = connection.cursor()

c.execute('''CREATE TABLE practice
             (id INTEGER NOT NULL,
             club TEXT PRIMARY KEY,
             direction INTEGER NOT NULL DEFAULT 0,
             hits INTEGER NOT NULL DEFAULT 0,
             distance INTEGER NOT NULL DEFAULT 0,
             total_distance INTEGER NOT NULL DEFAULT 0,
             total_hits INTEGER NOT NULL DEFAULT 0,
             average_distance INTEGER NOT NULL DEFAULT 0)''')

clubs = ['Driver', 'Fairway Wood', 'Hybrid', 'Iron', 'Wedge']
for i, club in enumerate(clubs):
    c.execute("INSERT INTO practice (id, club, direction, hits, distance) VALUES (?, ?, ?, ?, ?)", (i+1, club, 0, 0, 0))

connection.commit()
connection.close()

