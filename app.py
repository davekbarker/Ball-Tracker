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


# Define a route for adding a person
@app.route('/add_person', methods=['POST'])
def add_person():
    # Retrieve the form data
    name = request.form['name']
    age = request.form['age']
    print('Adding person:', name, age) # Add this line to print the data

    # Insert the new person into the database
    cursor = get_cursor()
    cursor.execute("INSERT INTO my_table (name, age) VALUES (?, ?)", (name, age))
    get_db().commit()

    # Redirect back to the index page
    return redirect('/')

# @app.route('/')
# def index():
#     return render_template('index.html')


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
    # Render the range_time.html template with the club names
    # return render_template('range_time.html', club_rows=club_rows, selected_club=selected_club)
    return render_template('range_time.html', club_rows=club_rows)
    # return render_template('range_time.html')


# Define a route for submitting the club direction
@app.route('/submit_direction', methods=['POST'])
def submit_direction():

    # Retrieve the form data
    club_id = request.form['club_name']
    direction = request.form['club_direction']

    print(club_id, direction)

    # Convert the direction to integer
    direction = int(direction)

    # Add 1 hit to the selected club
    conn = sqlite3.connect('clubs.db')
    c = conn.cursor()
    c.execute("UPDATE golf_clubs SET hits = hits + 1 WHERE id = ?", (club_id,))
    conn.commit()

    # Calculate the new average direction and update the selected club
    c.execute("SELECT direction, hits FROM golf_clubs WHERE id = ?", (club_id,))
    row = c.fetchone()
    current_direction = row[0]
    hits = row[1]
    new_direction = int((current_direction * hits + direction) / (hits + 1))
    # new_direction = (current_direction * hits + direction) / (hits + 1)
    c.execute("UPDATE golf_clubs SET direction = ? WHERE id = ?", (new_direction, club_id))
    conn.commit()

    # Close the connection
    conn.close()

    # Redirect back to the range time page
    return redirect(url_for('range_time', club_name=club_id))


@app.route('/current_stats')
def current_stats():
    conn = sqlite3.connect('clubs.db')
    c = conn.cursor()
    c.execute("SELECT name, direction, distance, hits FROM golf_clubs")
    rows = c.fetchall()
    conn.close()
    return render_template('current_stats.html', clubs=rows)


if __name__ == '__main__':
    app.run(debug=True)
