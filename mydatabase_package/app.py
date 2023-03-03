import sys
import sqlite3
from flask import Flask, render_template, g, request, redirect, url_for, session, jsonify
import time

# from mydatabase_package import auth
from mydatabase_package.auth import bp as auth_bp

app = Flask(__name__, template_folder='../templates')
# app = Flask(__name__, template_folder='/Users/Dave/PycharmProjects/mydatabase/templates')
# app = Flask(__name__, template_folder='/root/Ball-Tracker/templates')

app.config.from_mapping(
    SECRET_KEY='dev',
    DATABASE='database.sqlite',
    TEMPLATE_FOLDER='templates'
)

# app.register_blueprint(auth)
app.register_blueprint(auth_bp)


# Create a connection to the database
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('../my_database.db')
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


@app.route("/index")
def index():
    connection = sqlite3.connect("mydatabase.db")
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM my_table")
    rows = cursor.fetchall()
    connection.close()
    return render_template("index.html", rows=rows)


@app.route('/play_golf')
def play_golf():
    return render_template('play_golf.html')


@app.route('/range_time')
def range_time():
    # Connect to clubs.db
    # conn = sqlite3.connect('/Users/Dave/PycharmProjects/mydatabase/clubs.db')
    conn = sqlite3.connect('./clubs.db')
    c = conn.cursor()

    # Retrieve all club names from the golf_clubs table
    c.execute("SELECT id, name FROM golf_clubs")
    club_rows = c.fetchall()

    # Close the connection
    conn.close()

    selected_club = request.args.get('club_name')  # get the selected club from the URL query string
    return render_template('range_time.html', club_rows=club_rows)


@app.route('/submit_direction', methods=['POST'])
def submit_direction():
    if request.method == 'POST':
        club_id = int(request.form['club_name'])
        new_direction = int(request.form['direction'])
        # conn = sqlite3.connect('/Users/Dave/PycharmProjects/mydatabase/clubs.db')
        conn = sqlite3.connect('./clubs.db')
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
    conn = sqlite3.connect('./clubs.db')
    # conn = sqlite3.connect('/Users/Dave/PycharmProjects/mydatabase/clubs.db')
    c = conn.cursor()
    c.execute("SELECT name, direction, distance, hits FROM golf_clubs")
    rows = c.fetchall()
    conn.close()
    return render_template('current_stats.html', clubs=rows)


@app.route('/clear_stats', methods=['GET', 'POST'])
def clear_stats():
    # conn = sqlite3.connect('/Users/Dave/PycharmProjects/mydatabase/clubs.db')
    conn = sqlite3.connect('./clubs.db')
    c = conn.cursor()

    if request.method == 'POST':
        club_name = request.form['club_name']
        c.execute("UPDATE golf_clubs SET direction = 0, distance = 0, hits = 0 WHERE name = ?", (club_name,))
        conn.commit()
        return redirect(url_for('current_stats'))

    c.execute("SELECT name FROM golf_clubs")
    clubs = [row[0] for row in c.fetchall()]
    return render_template('clear_stats.html', clubs=clubs)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form values
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Connect to database.db
        conn = sqlite3.connect('/Users/Dave/PycharmProjects/mydatabase/database.db')

        c = conn.cursor()

        # Check if username already exists
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        if c.fetchone():
            # Username already exists, display error message
            error = "Username already exists. Please choose a different username."
            return render_template('register.html', error=error)

        # If username doesn't exist, insert new user into database
        c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, password))
        conn.commit()

        # Close the cursor and the connection
        c.close()
        conn.close()

        # Redirect to login page
        return redirect(url_for('login'))

    # If request method is GET, display register form
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form values
        username = request.form['username']
        password = request.form['password']

        # Connect to database
        # conn = sqlite3.connect('/Users/Dave/PycharmProjects/mydatabase/database.db')
        conn = sqlite3.connect('./database.db')
        c = conn.cursor()

        # Check if username and password are correct
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()

        if user:
            # If username and password are correct, redirect to home page
            session['user_id'] = user[0]  # Save user_id in session
            return redirect(url_for('home'))
        else:
            # If username and password are incorrect, display error message
            error = "Incorrect username or password. Please try again."
            return render_template('login.html', error=error)

        # Close the cursor and the connection
        c.close()
        conn.close()

    # If request method is GET, display login form
    return render_template('login.html')


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/practice', methods=['GET', 'POST'])
def practice():
    print("Inside print() dawg")
    # conn = sqlite3.connect('/Users/Dave/PycharmProjects/mydatabase/practice.db')
    conn = sqlite3.connect('./practice.db')
    c = conn.cursor()

    # Fetch practice data for dropdown
    # c.execute("SELECT DISTINCT club FROM practice")
    c.execute("SELECT * FROM practice")
    practice_data = c.fetchall()
    print("Inside print() dawg 2")
    print(practice_data)
    if request.method == 'POST':
        club = request.form['club']
        direction = request.form['direction']
        distance = request.form['distance']
        print("Inside print() dawg 3")
        c.execute("UPDATE practice SET direction = direction + ?, hits = hits + 1, distance = distance + ?,"
                  " total_distance = total_distance + ?, average_distance = total_distance / hits WHERE club = ?",
                  (int(direction), int(distance), int(distance), club))
        print("Inside print() dawg 4")
        conn.commit()
    print("Inside print() dawg 5")
    c.execute("SELECT * FROM practice")
    print("Inside print() dawg 6")
    data = c.fetchall()
    conn.close()
    print("Inside print() dawg 7")
    return render_template('practice.html', data=data, practice_data=practice_data)


@app.route('/submit_shot', methods=['POST'])
def submit_shot():
    print("submit_shot() made it capt'n!")
    try:
        club = request.form['club']
        distance = request.form['distance']
        direction = request.form['direction']

        # Print statements do not work here like this because we are redirecting to url
        # print(f"club: {club}, distance: {distance}, direction: {direction}")

        # conn = sqlite3.connect('/Users/Dave/PycharmProjects/mydatabase/practice.db')
        conn = sqlite3.connect('./practice.db')
        c = conn.cursor()

        try:
            # print("the attempt?")
            # Retrieve the current direction, hits, total_distance, and average_distance values for the selected club
            c.execute("SELECT * FROM practice WHERE club = ?", (club,))
            row = c.fetchone()

            # print("the attemptZZ?")
            # print(type(row[0]), type(row[1]), type(row[2]), type(row[3]), type(row[4]), type(row[5]), type(row[6]),
            #       type(row[7]))

            # Print statements do not work here like this because we are redirecting to url

            # print(
            # f"club: {club}, distance: {distance}, direction: {direction}")  # add this line to print the received data

            # # Print the values retrieved from the database
            # print(f"Current id: {row[0]}, Current club: {row[1]},
            #   Current direction: {row[2]}, Current distance: {row[3]}")
            # print(f"Current direction: {row[2]}, hits: {row[3]},
            #   total_distance: {row[5]}, average_distance: {row[7]}")

            if row is None:
                # print("the attempt 2")
                current_direction = direction
                hits = 0
                total_distance = 0
                average_distance = 0
            else:
                # print("the attempt 3")
                current_direction = row[2]
                hits = row[3]
                total_distance = row[5]
                average_distance = row[7]
                # (current_direction,), (hits,), (total_distance,), (average_distance,) = row
                print("the attempt 4??")
            # Calculate the new direction based on the current direction, number of hits, and new direction
            average_direction = (current_direction * hits + int(direction)) / (hits + 1)
            # print(f"New direction: {average_direction}")
            # print("capt4")

            # Calculate the new total_distance and average_distance based on the current total_distance,
            # average_distance, and new_distance
            new_total_distance = total_distance + int(distance)
            average_distance = new_total_distance / (hits + 1)
            # print(f"New total distance: {new_total_distance}, new average distance: {average_distance}")
            # print("capt3")

            # Increment the hits column by 1 and update the direction, total_distance, and average_distance columns
            if row is None:
                c.execute("INSERT INTO practice (club, direction, hits, total_distance, average_distance) "
                          "VALUES (?, ?, 1, ?, ?)", (club, round(average_direction), new_total_distance,
                                                     round(average_distance)))
                # print("row added to database Capt'n")

            else:
                c.execute("UPDATE practice SET hits = hits + 1, direction = ?, total_distance = ?, average_distance = ?"
                          " WHERE club = ?", (round(average_direction), new_total_distance, round(average_distance),
                                              club))
                # print("row updated to database Capt'n")

            conn.commit()
            message = "shot submitted successfully Capt'n"
        except:
            conn.rollback()
            # print("capt2")
            print("Error updating database:", sys.exc_info()[0])
            message = "Error updating database: {}".format(sys.exc_info()[0])
        finally:
            conn.close()

        return redirect(url_for('practice'))

    except:
        print("capt1")
        print("Error submitting shot:", sys.exc_info()[0])
        return 'Error submitting shot', 500


@app.route('/end_practice', methods=['POST'])
def end_practice():
    # conn = sqlite3.connect('/Users/Dave/PycharmProjects/mydatabase/practice.db')
    conn = sqlite3.connect('./practice.db')
    c = conn.cursor()
    c.execute("UPDATE practice SET direction = 0, distance = 0, hits = 0, total_distance = 0, total_hits = 0, "
              "average_distance = 0")
    conn.commit()
    conn.close()
    return redirect('/')


@app.route('/practice_stats', methods=['GET', 'POST'])
def practice_stats():
    # conn = sqlite3.connect('/Users/Dave/PycharmProjects/mydatabase/practice.db')
    conn = sqlite3.connect('./practice.db')
    c = conn.cursor()
    # c.execute("SELECT club, hits, total_distance, average_distance, direction FROM practice")
    c.execute("SELECT * FROM practice")
    print("capt practice_stats")
    practice_data = c.fetchall()
    print(practice_data)
    conn.close()
    print("practice_stats 2")
    print(practice_data)
    return jsonify(practice_data)


if __name__ == '__main__':
    app.run(debug=True)
