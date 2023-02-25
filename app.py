import sys

from flask import Flask, render_template, request, redirect, g, url_for
import sqlite3

app = Flask(__name__)

# Create a connection to the database
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('my_database.db')
        # g.db = sqlite3.connect('clubs.db')
    return g.db


def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


@app.teardown_appcontext
def teardown_db(exception):
    close_db()


# Create a cursor object
def get_cursor():
    db = get_db()
    if 'cursor' not in g:
        g.cursor = db.cursor()
    return g.cursor


def close_cursor(e=None):
    cursor = g.pop('cursor', None)
    if cursor is not None:
        cursor.close()


@app.teardown_request
def teardown_cursor(exception):
    close_cursor()


# Define a route for the index page
@app.route('/')
def index():
    # Retrieve all rows from the table
    cursor = get_cursor()
    cursor.execute("SELECT * FROM my_table")
    rows = cursor.fetchall()

    # Render the index template with the retrieved data
    return render_template('index.html', rows=rows)


@app.route('/play_golf')
def play_golf():
    return render_template('play_golf.html')


@app.route('/range_time')
def range_time():
    # Connect to clubs.db
    conn = sqlite3.connect('clubs.db')
    c = conn.cursor()

    # Retrieve all club names from the golf_clubs table
    c.execute("SELECT id, name FROM golf_clubs")
    club_rows = c.fetchall()

    # Close the connection
    conn.close()
    selected_club = request.args.get('club_name')  # get the selected club from the URL query string
    return render_template('range_time.html', club_rows=club_rows)


#<<<<<<<<<<THIS ONE WORKS>>>>>>>>>>>
@app.route('/submit_direction', methods=['POST'])
def submit_direction():
    if request.method == 'POST':
        club_id = int(request.form['club_name'])
        new_direction = int(request.form['direction'])

        conn = sqlite3.connect('clubs.db')
        c = conn.cursor()

        try:
            # Retrieve the current direction and hits values for the selected club
            c.execute("SELECT direction, hits FROM golf_clubs WHERE id = ?", (club_id,))
            current_direction, hits = c.fetchone()

            # Calculate the new direction based on the current direction, number of hits, and new direction
            new_direction = (current_direction * hits + new_direction) / (hits + 1)

            # Increment the hits column by 1 and update the direction column
            c.execute("UPDATE golf_clubs SET hits = hits + 1, direction = ? WHERE id = ?", (new_direction, club_id))

            conn.commit()
            message = "Club direction has been updated."
        except:
            conn.rollback()
            message = "Error updating database: {}".format(sys.exc_info()[0])
        finally:
            conn.close()

        return redirect(url_for('range_time', club_name=club_id, msg=message))


@app.route('/current_stats')
def current_stats():
    conn = sqlite3.connect('clubs.db')
    c = conn.cursor()
    c.execute("SELECT name, direction, distance, hits FROM golf_clubs")
    rows = c.fetchall()
    conn.close()
    return render_template('current_stats.html', clubs=rows)


@app.route('/clear_stats', methods=['GET', 'POST'])
def clear_stats():
    conn = sqlite3.connect('clubs.db')
    c = conn.cursor()

    if request.method == 'POST':
        club_name = request.form['club_name']
        c.execute("UPDATE golf_clubs SET direction = 0, distance = 0, hits = 0 WHERE name = ?", (club_name,))
        conn.commit()
        return redirect(url_for('current_stats'))

    c.execute("SELECT name FROM golf_clubs")
    clubs = [row[0] for row in c.fetchall()]
    return render_template('clear_stats.html', clubs=clubs)


if __name__ == '__main__':
    app.run(debug=True)
