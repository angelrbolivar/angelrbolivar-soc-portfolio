from flask import Flask, render_template, session, redirect, url_for, Response
from flask_session import Session    # let us use login sessions
import random
import sqlite3
from datetime import datetime  # record each time alert was created

# AI Assistance Disclosure:
# I used Grok (xAI) as an AI assistant to help with code structure, debugging, adding detailed comments, implementing the CSV export feature, and improving overall organization.
# All core logic, fraud rules, database design, and architecture decisions were made by me based on my 2.5 years of real experience at Remitly.

# Creates the main Flask web app object
app = Flask(__name__)

# session settings (imported from week9 psets)
# need to use session so the alerts stay on the page even if page is refreshed
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# function to generate alerts


def generate_alert():
    # declarations of corridors to be used
    countries = ["Colombia", "Mexico", "Dominican Republic", "USA", "Spain"]
    # transaction amounts in USD
    amount = random.randint(300, 6500)
    # choosing sender country ramdomly
    sender = random.choice(countries)
    # choosing recveining country ramdomly
    receiver = random.choice(countries)
    # generating ramdom ip adresses
    # the f at the beginning is used to indicate the program to run the functions inside the curly braces
    ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"

    # simulating gender checks
    # profile gender means the gender of the customer registered on the system
    profile_gender = random.choice(["Male", "Female"])
    # caller gender means the gender of the customer on the call (if voice is a female or a male)
    caller_gender = random.choice(["Male", "Female"])
    rule = None
    severity = "Low"

    # If sender country is Col, Mex or Dom and the amount sent is higher than 1800, please flag it as high risk
    if sender in ["Colombia", "Mexico", "Dominican Republic"] and amount > 1800:
        rule = "High-risk corridor + high amount"
        severity = "High"
    # if the gender heard on the call is the voice of a lady but the profile says it is a man then there is something going on
    elif profile_gender != caller_gender:
        rule = "Gender mismatch (Account take over suspect)"
        severity = "High"
    # ramdom generation of different risks
    elif random.random() < 0.40:
        rule = "PEP or OFAC match"
        severity = "High"
    elif random.random() < 0.35:
        rule = "Velocity check failed (too many transactions)"
        severity = "Medium"
    elif random.random() < 0.30:
        rule = "Money Mule pattern + stolen info"
        severity = "High"
    elif random.random() < 0.25:
        rule = "Brute-force / Account Take Over detected"
        severity = "High"
    # create an alert as long as there is a present rule
    # this will print for example:  id 1000, money mule pattern + stolen info, severity HIGH, status Open, details: colombia to mexico | 500 usd | IP: 023409304 | Profile: man, caller: lady.
    if rule:
        # send this back to whoever called the function... the {...} with colons :   creates  a dictionary
        return {
            # creates randon number between 1000 and 9999
            "id": random.randint(1000, 9999),
            "rule": rule,  # put the rule name that was triggered previously
            "severity": severity,  # puts high, medium or low
            "status": "Open",  # always starts as "Open"
            # the f at the beginning means f-string(format string)
            # it is used to mix text + variables
            "details": f"{sender} - {receiver} | ${amount} | IP: {ip} | Profile: {profile_gender}, Caller: {caller_gender}"
        }
    # if no rule was triggered functions return None -> give nothing
    return None

# definition of a function to initialize database, the curly empty () means this function doesn't need extra info to run


def init_db():
    """creates database file and table the first time the app runs."""
    # sqlite3 is the build in python library to handle databases....
    # .connect('fraudetective.db') open or create a file called fraudetective.db
    # we save the connection in variable db
    db = sqlite3.connect('fraudetective.db')
    # tells database to run the command.
    # triple quotes are used because command is long and it does have many lines
    # creates a table called alerts if it does not exist already.
    db.execute('''CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY,
                    rule TEXT,
                    severity TEXT,
                    status TEXT,
                    details TEXT,
                    timestamp TEXT)''')
    # this is to make the table not be temporary but to be saved
    db.commit()
    # closes the connection to the database
    db.close()

# definition of a function to connect with database, the curly empty () means this function doesn't need extra info to run


def get_db_connection():
    """Returns a connection to the database (used by every route)."""
    # .connect('fraudetective.db') open or create a file called fraudetective.db
    db = sqlite3.connect('fraudetective.db')
    # ensure the data retrived will be presented as a dictionaries
    # thanks to this line we can call the information using: alert['id'] alert ['rule'] etc
    db.row_factory = sqlite3.Row  # makes rows behave like dictionaries
    # give the connection back to whoever called the function.
    return db


# run once when the app starts
# this creates the table the very first time somebody runs the app
init_db()

# database is ready


@app.route("/")
def index():
    return render_template("index.html")

# dashboard page


@app.route("/dashboard")
def dashboard():
    """Main SOC Dashboard - now loads alerts from SQLite database"""
    # calls the function to get the connection to the database and it stores in db variable so we can handle it
    db = get_db_connection()
    # asks the database for all of the alerts
    # sorting them from newest to oldest
    # .fetchall() is to get all results at once.
    alerts = db.execute(
        'SELECT * FROM alerts ORDER BY timestamp DESC').fetchall()
    # closes connection to database
    db.close()
    # go to dashboard.html
    # converts the database rows into dictionaries to be read easier by table and charts.
    # alerts = "create variable"
    # [ create a list ]
    # dict(row) " take a row and turn into a python dict
    # for row in alerts " do this for every single row that came from the database"
    return render_template("dashboard.html", alerts=[dict(row) for row in alerts])


@app.route("/generate")
def generate():
    """Generate new alerts and save it to the database permanently."""
    # iterate from 0 to 29
    for _ in range(30):
        # create a variable for each row to store its generated alert
        alert = generate_alert()
        # as long as there is an alert
        if alert:
            # create a db variable and get connection with the database
            db = get_db_connection()
            # execute command to insert information into alerts table
            # add new row in alerts table
            # the () tells the database which columns to fill
            # VALUES (?,?) tells sql that values will be provided in the next line (avoid sql injection)
            db.execute('''INSERT INTO alerts (id, rule, severity, status, details, timestamp)
                                 VALUES (?, ?, ?, ?, ?, ?)''',
                       # data that will be added... and new function to get current time
                       (alert['id'], alert['rule'], alert['severity'], alert['status'], alert['details'], datetime.now().strftime("%Y-%m-%d %H:%M")))
            # save the changes
            db.commit()
            # closes connection to database
            db.close()
    # Go back to dashboard to see new alerts
    return redirect(url_for('dashboard'))

# the part <int:alert_id> and <action> in the route line means that flask will take what is on the url
# and give it to us as variable
# alert_id = is the number of the alert.
# action = is the word from the button clicked (suspended, approved, escalated)
# so basically Flask turns a button click into a python variable.


@app.route("/triage/<int:alert_id>/<action>")
def triage(alert_id, action):
    """update status in real time database and redirects back to dashboard"""
    # connect to database
    db = get_db_connection()
    # execute command to update database.... placeholders '?' indicate that information will be given in next line
    db.execute('UPDATE alerts SET status = ? WHERE id = ?',
               # action.capitalize basically just make 'approve' to 'Approve', and the alert id is the number of the alert
               (action.capitalize(), alert_id))
    # save the changes
    db.commit()
    # closes connection to database
    db.close()
    # Go back to dashboard
    return redirect(url_for('dashboard'))


@app.route("/clear")
def clear():
    """Clear alerts from db"""
    # connects to database and made db variable to handle it
    db = get_db_connection()
    # executing command in database to delete... in this case all of the alerts.
    db.execute('DELETE FROM alerts')
    # save it
    db.commit()
    # close connection with database
    db.close()
    # return user to dashboard page
    return redirect(url_for('dashboard'))

@app.route("/export")
def export():
    """Export all alerts to CSV file for downloading
    it is triggered when user clicks the export to csv button on the dashboard.
    exporting data from the database"""

    # connect to the database
    db = get_db_connection()
    # get all alerts from database newest first and store it in alerts variable
    alerts = db.execute('SELECT * FROM alerts ORDER BY timestamp DESC').fetchall()
    # closing database connection
    db.close()

    # we import io for creating a file like object in memory instead of server.
    import io
    # we import the python library to handle csvs
    import csv

    # creating a text file in memory
    output = io.StringIO()
    # creation of a CSV writer objetc that writes into our file in memory 'output'
    writer = csv.writer(output)
    # write the header row that will appear in the csv... column names (this will appear on first line of the csv file)
    writer.writerow(["ID","Rule", "Severity", "Status", "Details", "Timestamp"])

    # iterating over every alert and writing it as new row in the CSV
    for alert in alerts:
        writer.writerow([alert["id"], alert["rule"], alert["severity"],
                        alert["status"], alert["details"], alert["timestamp"]])
    # return the CSV file to user's browser for download.
    # Response is an special flask objetc that allow us to send files.
    return Response(
        output.getvalue(), # the csv text
        mimetype="text/csv", # indicates browser this is a CSV
        headers={"Content-Disposition": "attachment; filename=fdetect_alerts.csv"} # forces browser to download the file immediately
    )

# START SERVER
if __name__ == "__main__":
    app.run(debug=True)  # with debug=True shows error messages for debugging.
