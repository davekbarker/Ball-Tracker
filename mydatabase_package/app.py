import bcrypt
import os
import sys
import sqlite3
from flask import Flask, render_template, g, request, redirect, url_for, session, jsonify
from flask_session import Session
# from flask_login import LoginManager

# DATABASES_DIR = "/Users/Dave/PycharmProjects/mydatabase/databases/"
# from mydatabase_package import auth
#from mydatabase_package.auth import bp as auth_bp

app = Flask(__name__, template_folder='../templates')
# app = Flask(__name__, template_folder='/Users/Dave/PycharmProjects/mydatabase/templates')
# app = Flask(__name__, template_folder='/root/Ball-Tracker/templates')

# Configure Flask-Session
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './session_files'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_FILE_THRESHOLD'] = 100
app.config['SESSION_FILE_MODE'] = 0o600

Session(app)

app.config.from_mapping(
    SECRET_KEY='dev',
    DATABASE='database.sqlite',
    TEMPLATE_FOLDER='templates'
)

# app.register_blueprint(auth)
#app.register_blueprint(auth_bp)


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
    # 2 '..' for droplet
    # connection = sqlite3.connect("../mydatabase.db")
    connection = sqlite3.connect("./mydatabase.db")
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM my_table")
    rows = cursor.fetchall()
    connection.close()
    return render_template("index.html", rows=rows)


@app.route('/play_golf')
def play_golf():
    return render_template('play_golf.html')


@app.route('/wrongUser')
def wrongUser():
    return render_template('wrongUser.html')


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
    print("In register()")
    print(os.getcwd())
    # Get the IP address of the user
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    # ip_address = request.remote_addr
    print(f"ip address: {ip_address}")

    if request.method == 'POST':
        # Get form values
        name = request.form['name']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirmPassword']
        print(name, username, email, password, ip_address, confirm_password)

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        # hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        print(hashed_password)
        print(name, username, email, hashed_password, ip_address)

        # # Connect to database.db
        # conn = sqlite3.connect('/Users/Dave/PycharmProjects/mydatabase/database.db')
        # c = conn.cursor()
        print(f"{username}.db")
        # db_file = os.path.join('/Users/Dave/PycharmProjects/mydatabase', f"{username}.db")
        # db_file = os.path.join('/Users/Dave/golfers', username, f"{username}.db")
        db_file = f"{username}.db"
        # conn = sqlite3.connect(db_file)

        # Get the absolute path of the file
        # db_file_path = os.path.abspath(db_file)
        # print(f"Abspath is: {db_file_path}")

        # Check if the user database file already exists
        if os.path.exists(db_file):
            error = "Username already exists. Please choose a different username."
            print("Should show error for username existing:", error)
            return render_template('register.html', error=error)

        else:
            # If user database file does not exist, create a new one for the user
            print(f"Creating database for user: {username}")
            # ##### conn = sqlite3.connect(db_file) ######
            print(f"Database in progress for user: {username}")
            # c = conn.cursor()

            # Create the users table in the database
            # ##### conn.execute('''CREATE TABLE IF NOT EXISTS users
            # #####              (name text, username text, email text, password blob, ip_address integer)''')
            # ##### conn.commit()
            # print(f"Database being assembled for user: {username}")
            # # Insert new user into database
            # ##### conn.execute("INSERT INTO users (name, username, email, password, ip_address) VALUES (?, ?, ?, ?, ?)",
            # #####              (name, username, email, hashed_password, ip_address))
            # ##### conn.commit()
            print(f"Database assembled for user: {username}")

            # Not sure about this code.......
            # Create the practice table in the user's database
            create_user_database(name, username, email, hashed_password, ip_address)
            print(f"Database completely assembled for user: {username}")


            # Close the cursor and the connection
            # c.close()
            # ##### conn.close()
            print(f"Database created for user: {username}")
            # Redirect to login page
            return redirect(url_for('login'))

    # If request method is GET, display register form
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    print("inside login()")
    if request.method == 'POST':
        # Get form values
        username = request.form['username']
        password = request.form['password']

        if os.path.isfile(f"{username}.db"):
            print(f"Accessing database for user: {username}")
            conn = sqlite3.connect(f"{username}.db")
            print(f"Accessed database for user: {username}")
            print(f"Username: {username} Password: {password}")
            c = conn.cursor()

            # ***** There is still a bug right here..... if you access a .db without a 'users' table it will crash ****
            # ***** Will fix when it's an issue, all it should need is another if/else block, long hair no care *****
            # Get the hashed password for the user
            # c.execute("SELECT password FROM users WHERE username=?", (username,))
            c.execute("SELECT * FROM user WHERE username=?", (username,))
            result = c.fetchone()

            if result:
                print("inside IF")
                # Verify password using the stored hash
                if bcrypt.checkpw(password.encode('utf-8'), result[3]):
                    print("inside IF IF")
                    # If username and password are correct, redirect to dashboard page
                    session['username'] = username  # Save username in session
                    print(f"Session username set: {session['username']}")
                    return redirect(url_for('dashboard'))
            else:
                # If username and password are incorrect, display error message
                error = "Incorrect username or password. Please try again."
                print(f"Error should display: {error}")
                # return render_template('login.html', error=error)
                # return redirect(url_for('login', error=error))
                return redirect(url_for('wrongUser', error='Incorrect username or password. Please try again.'))

            # Close the cursor and the connection
            c.close()
            conn.close()
        else:
            error = "User does not exist."
            return redirect(url_for('wrongUser', error=error))

    # If request method is GET, display login form
    return render_template('login.html')
    # return redirect(url_for('login', message='You have successfully registered.'))


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/changelog')
def changelog():
    return render_template('changelog.html')


@app.route('/range_user')
def range_user():
    # EDIT THIS TO MAKE THE SHIT WORK**********
    if 'username' in session:
        username = session['username']
        print(f"Session: {session}")

        conn = sqlite3.connect(get_user_database_filename(username))
        c = conn.cursor()

        c.execute("SELECT * FROM clubs")
        user_club_data = c.fetchall()

        return render_template("range_user.html", user_club_data=user_club_data, username=username)



        # return render_template('range_user.html', username=username)
    else:
        return redirect(url_for('login'))


@app.route('/edit_clubs')
def edit_clubs():
    if 'username' in session:
        username = session['username']
        print(f"Session: {session}")
        return render_template('edit_clubs.html', username=username)
    else:
        return redirect(url_for('login'))


@app.route('/putt_user')
def putt_user():
    if 'username' in session:
        username = session['username']
        print(f"Session: {session}")

        conn = sqlite3.connect(get_user_database_filename(username))
        c = conn.cursor()

        c.execute("SELECT * FROM putts")
        user_putt_data = c.fetchall()

        return render_template('putt_user.html', username=username, user_putt_data=user_putt_data)
    else:
        return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        username = session['username']
        print(f"Session: {session}")
        return render_template('dashboard.html', username=username)
    else:
        return redirect(url_for('login'))


@app.route('/practice_page')
def practice_page():
    if 'username' in session:
        username = session['username']
        print(f"Session: {session}")
        return render_template('practice_page.html', username=username)
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    # Remove the 'username' from the session if it's there
    session.pop('username', None)

    # Redirect the user to the login or home page
    return redirect(url_for('home'))


# @app.route('/dashboard')
# def dashboard():
#     # username = current_user.username
#     # return render_template('dashboard.html', username=username)
#     return render_template('dashboard.html')


# NOT USED CAPT'N <--- These are lies
def get_user_database_filename(username):
    # will most likely need to change to '..' deployed
    # return f'./user_{user_id}.db'
    return f'{username}.db'


def get_database_filename(ip_address):
    # will most likely need to change to '..' deployed
    return f'./practice.{ip_address}.db'


def create_user_database(username, name, email, hashed_password, ip_address):
    conn = sqlite3.connect(get_user_database_filename(username))
    c = conn.cursor()

    # Create the users table
    c.execute('''CREATE TABLE IF NOT EXISTS user 
              (name TEXT, username TEXT PRIMARY KEY, email TEXT, password BLOB, ip_address TEXT,
              first_visit TIMESTAMP DEFAULT CURRENT_TIMESTAMP, last_visit TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

    # Insert the user's information into the users table
    # c.execute("INSERT INTO users (name, username, email, password, ip_address) VALUES (?, ?, ?, ?, ?)",
    #           (name, username, email, hashed_password, ip_address))
    c.execute("INSERT INTO user (name, username, email, password, ip_address) \
               VALUES (?, ?, ?, ?, ?)", (name, username, email, hashed_password, ip_address))

    # Create the table
    c.execute('''CREATE TABLE clubs
             (id INTEGER NOT NULL,
             club TEXT PRIMARY KEY,
             direction INTEGER NOT NULL DEFAULT 0,
             hits INTEGER NOT NULL DEFAULT 0,
             distance INTEGER NOT NULL DEFAULT 0,
             total_distance INTEGER NOT NULL DEFAULT 0,
             total_hits INTEGER NOT NULL DEFAULT 0,
             average_distance INTEGER NOT NULL DEFAULT 0,
             username TEXT)''')

    clubs = ['Driver', 'Wood', 'Hybrid', 'Iron', 'Wedge']
    for i, club in enumerate(clubs):
        c.execute("INSERT INTO clubs (id, club, direction, hits, distance, total_distance, total_hits, "
                  "average_distance, username) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  (i + 1, club, 0, 0, 0, 0, 0, 0, username))

    c.execute('''CREATE TABLE putts
                 (actual_distance INTEGER PRIMARY KEY,
                  average_distance INTEGER NOT NULL DEFAULT 0,
                  average_direction INTEGER NOT NULL DEFAULT 0,
                  average_putts INTEGER NOT NULL DEFAULT 0,
                  hits INTEGER NOT NULL DEFAULT 0,
                  total_distance NOT NULL DEFAULT 0)''')

    distances = [1, 3, 5, 8, 10, 13, 15, 18, 20]
    for distance in distances:
        c.execute("INSERT INTO putts (actual_distance, average_distance, average_direction, average_putts, hits, "
                  "total_distance) VALUES (?, ?, ?, ?, ?, ?)",
                  (distance, 0, 0, 0, 0, 0))

    # Save (commit) the changes
    conn.commit()

    # Close the connection
    conn.close()


def create_new_database(ip_address):
    conn = sqlite3.connect(get_database_filename(ip_address))
    c = conn.cursor()

    # Create the table
    c.execute('''CREATE TABLE practice
             (id INTEGER NOT NULL,
             club TEXT PRIMARY KEY,
             direction INTEGER NOT NULL DEFAULT 0,
             hits INTEGER NOT NULL DEFAULT 0,
             distance INTEGER NOT NULL DEFAULT 0,
             total_distance INTEGER NOT NULL DEFAULT 0,
             total_hits INTEGER NOT NULL DEFAULT 0,
             average_distance INTEGER NOT NULL DEFAULT 0,
             ip TEXT,
             last_visit TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

    clubs = ['Driver', 'Fairway Wood', 'Hybrid', 'Iron', 'Wedge']
    for i, club in enumerate(clubs):
        c.execute("INSERT INTO practice (id, club, direction, hits, distance, total_distance, total_hits, "
                  "average_distance, ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  (i + 1, club, 0, 0, 0, 0, 0, 0, ip_address))

    # Save (commit) the changes
    conn.commit()

    # Close the connection
    conn.close()


@app.route('/practice', methods=['GET', 'POST'])
def practice():
    # Get the IP address of the user
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    # ip_address = request.remote_addr
    print("Inside practice() dawg")
    print(f"ip address: {ip_address}")

    # Check if a database for this IP address exists
    if not os.path.exists(get_database_filename(ip_address)):
        create_new_database(ip_address)

    # conn = sqlite3.connect('/Users/Dave/PycharmProjects/mydatabase/practice.db')
    # conn = sqlite3.connect('./practice.db')
    conn = sqlite3.connect(get_database_filename(ip_address))
    c = conn.cursor()

    # Fetch practice data for dropdown
    # c.execute("SELECT DISTINCT club FROM practice")
    c.execute("SELECT * FROM practice")
    practice_data = c.fetchall()
    print("Inside practice() dawg 2")
    print(practice_data)
    if request.method == 'POST':
        club = request.form['club']
        direction = request.form['direction']
        distance = request.form['distance']
        print("Inside practice() dawg 3")
        print(practice_data)
        c.execute("UPDATE practice SET direction = direction + ?, hits = hits + 1, distance = distance + ?,"
                  " total_distance = total_distance + ?, average_distance = total_distance / hits WHERE club = ?",
                  (int(direction), int(distance), int(distance), club))
        print("Inside practice() dawg 4")
        conn.commit()
    print("Inside practice() dawg 5")
    c.execute("SELECT * FROM practice")
    print("Inside practice() dawg 6")
    data = c.fetchall()
    conn.close()
    print("Inside practice() dawg 7")
    return render_template('practice.html', data=data, practice_data=practice_data)


@app.route('/submit_shot', methods=['POST'])
def submit_shot():
    print("submit_shot() made it capt'n!")
    try:
        club = request.form['club']
        distance = request.form['distance']
        direction = request.form['direction']
        print(f"club: {club} distance: {distance} direction: {direction}")
        # Get the IP address of the user
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        # ip_address = request.remote_addr
        print("Inside submit_shot() dawg")
        print(f"ip address: {ip_address}")

        # Check if a database for this IP address exists
        if not os.path.exists(get_database_filename(ip_address)):
            create_new_database(ip_address)

        # Connect to the database
        conn = sqlite3.connect(get_database_filename(ip_address))
        c = conn.cursor()

        # Print statements do not work here like this because we are redirecting to url
        # print(f"club: {club}, distance: {distance}, direction: {direction}")

        # conn = sqlite3.connect('/Users/Dave/PycharmProjects/mydatabase/practice.db')
        # conn = sqlite3.connect('./practice.db')
        # c = conn.cursor()

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


@app.route('/user_submit_putt', methods=['POST'])
def user_submit_putt():
    print("user_submit_putt() made it capt'n!")

    if 'username' in session:
        username = session['username']
        print(f"{username} made it inside user_submit_putt")
        try:
            actual_distance = request.form['actual_distance']
            distance = request.form['distance']
            direction = request.form['direction']
            print(f"actual distance: {actual_distance} distance: {distance} direction: {direction}")

            # Get the IP address of the user
            ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
            # ip_address = request.remote_addr
            print("Inside INSIDE user_submit_putt dawg")
            print(f"ip address: {ip_address}")

            # Connect to the database
            conn = sqlite3.connect(get_user_database_filename(username))
            c = conn.cursor()

            # Retrieve the values for the selected distance
            c.execute("SELECT * FROM putts WHERE actual_distance = ?", (actual_distance,))
            row = c.fetchone()

            if row is None:
                average_direction = direction
                hits = 0
                total_distance = 0
                average_distance = 0
            else:
                average_direction = row[2]
                hits = row[4]
                total_distance = row[5]
                average_distance = row[1]

            # Calculate the new average_direction based on the current average_direction, number of hits, and new direction
            new_average_direction = (average_direction * hits + direction) / (hits + 1)
            print(f"new_average_direction: {new_average_direction}")
            # Calculate the new total_distance and average_distance based on the current total_distance,
            new_total_distance = total_distance + distance
            print(f"new_total_distance: {new_total_distance}")
            new_average_distance = new_total_distance / (hits + 1)
            print(f"new_average_distance: {new_average_distance}")

            # Increment the hits column by 1 and update the average_direction, total_distance, and average_distance columns
            if row is None:
                c.execute(
                    "INSERT INTO putts (actual_distance, average_distance, average_direction, hits, total_distance) "
                    "VALUES (?, ?, ?, 1, ?)",
                    (actual_distance, round(new_average_distance), round(new_average_direction),
                     new_total_distance))
            else:
                c.execute(
                    "UPDATE putts SET hits = hits + 1, average_direction = ?, total_distance = ?, average_distance = ?"
                    " WHERE actual_distance = ?",
                    (round(new_average_direction), new_total_distance, round(new_average_distance),
                     actual_distance))

            conn.commit()
            message = "user_submit_putt submitted successfully Capt'n"
        except:
            conn.rollback()
            print("Error updating user_submit_putt:", sys.exc_info()[0])
            message = "Error UPDATING database: {}".format(sys.exc_info()[0])
        finally:
            conn.close()

        return redirect(url_for('range_user'))

    else:
        return redirect(url_for('login'))



@app.route('/user_submit_range', methods=['POST'])
def user_submit_range():
    print("user_submit_range() made it capt'n!")

    if 'username' in session:
        username = session['username']
        print(f"{username} made it inside user_submit_range")
        try:
            club = request.form['club']
            distance = request.form['distance']
            direction = request.form['direction']
            print(f"club: {club} distance: {distance} direction: {direction}")

            # Get the IP address of the user
            ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
            # ip_address = request.remote_addr
            print("Inside INSIDE user_submit_range dawg")
            print(f"ip address: {ip_address}")

            # Connect to the database
            conn = sqlite3.connect(get_user_database_filename(username))
            c = conn.cursor()


            try:
                # Retrieve the current direction, hits, total_distance, and average_distance values for the selected club
                c.execute("SELECT * FROM clubs WHERE club = ?", (club,))
                row = c.fetchone()

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

                # Calculate the new total_distance and average_distance based on the current total_distance,
                new_total_distance = total_distance + int(distance)
                average_distance = new_total_distance / (hits + 1)

                # Increment the hits column by 1 and update the direction, total_distance, and average_distance columns
                if row is None:
                    c.execute("INSERT INTO clubs (club, direction, hits, total_distance, average_distance) "
                              "VALUES (?, ?, 1, ?, ?)", (club, round(average_direction), new_total_distance,
                                                         round(average_distance)))
                    # print("row added to database Capt'n")

                else:
                    c.execute("UPDATE clubs SET hits = hits + 1, direction = ?, total_distance = ?, average_distance = ?"
                              " WHERE club = ?", (round(average_direction), new_total_distance, round(average_distance),
                                                  club))
                    # print("row updated to database Capt'n")

                conn.commit()
                message = "user_submit_range submitted successfully Capt'n"
            except:
                conn.rollback()
                # print("capt2")
                print("Error updating user_submit_range:", sys.exc_info()[0])
                message = "Error UPDATING database: {}".format(sys.exc_info()[0])
            finally:
                conn.close()

            return redirect(url_for('range_user'))

        except:
            print("capt1")
            print("Error SUBMITTING user_submit_range:", sys.exc_info()[0])
            return 'Error submitting shot', 500

    else:
        return redirect(url_for('login'))


@app.route('/end_practice', methods=['POST'])
def end_practice():

    # Get the IP address of the user
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    # ip_address = request.remote_addr
    print("Inside end_practice() dawg")
    print(f"ip address: {ip_address}")

    # Check if a database for this IP address exists
    if not os.path.exists(get_database_filename(ip_address)):
        create_new_database(ip_address)

    # Connect to the database
    conn = sqlite3.connect(get_database_filename(ip_address))
    c = conn.cursor()

    # conn = sqlite3.connect('/Users/Dave/PycharmProjects/mydatabase/practice.db')
    # conn = sqlite3.connect('./practice.db')
    # c = conn.cursor()
    c.execute("UPDATE practice SET direction = 0, distance = 0, hits = 0, total_distance = 0, total_hits = 0, "
              "average_distance = 0")
    conn.commit()
    conn.close()
    return redirect('/')


@app.route('/practice_stats', methods=['GET', 'POST'])
def practice_stats():

    # Get the IP address of the user
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    print("Inside practice_stats() dawg")
    print(f"ip address: {ip_address}")

    # Check if a database for this IP address exists
    if not os.path.exists(get_database_filename(ip_address)):
        create_new_database(ip_address)

    # Connect to the database
    conn = sqlite3.connect(get_database_filename(ip_address))
    c = conn.cursor()

    # conn = sqlite3.connect('/Users/Dave/PycharmProjects/mydatabase/practice.db')
    # conn = sqlite3.connect('./practice.db')
    # c = conn.cursor()
    # c.execute("SELECT club, hits, total_distance, average_distance, direction FROM practice")
    c.execute("SELECT * FROM practice")
    print("capt practice_stats")
    practice_data = c.fetchall()
    # print(practice_data)
    conn.close()
    print("practice_stats 2")
    print(practice_data)
    return jsonify(practice_data)


# practice_stats turned to user_stats
@app.route('/user_stats', methods=['GET', 'POST'])
def user_stats():

    if 'username' in session:
        username = session['username']

        conn = sqlite3.connect(get_user_database_filename(username))
        c = conn.cursor()

        c.execute("SELECT * FROM clubs")
        print("capt user_stats 1")
        user_club_data = c.fetchall()

        c.execute("SELECT * FROM putts")
        print("capt user_stats 2")
        user_putt_data = c.fetchall()

        print(f"Session: {session}")
        print("user_stats 3")
        print(f"user club data: {user_club_data}")
        print(f"user putt data: {user_putt_data}")
        return jsonify(user_putt_data, user_club_data)
    else:
        return redirect(url_for('login'))



if __name__ == '__main__':
    app.run(debug=True)
