from flask import Flask, render_template, url_for, request, abort, redirect
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from db import DBconfig
from os import urandom
import scrypt
import base64


app = Flask(__name__)

DBconfig = DBconfig()

# COnfigure DB
app.config['MYSQL_HOST'] = DBconfig["host"]
app.config['MYSQL_USER'] = DBconfig["user"]
app.config['MYSQL_PASSWORD'] = DBconfig["password"]
app.config['MYSQL_DB'] = DBconfig["DBName"]
app.config['MYSQL_CURSORCLASS'] = DBconfig["dictDB"]

# init MYSQL
mysql = MySQL(app)

def is_logged_in(flask_request: Flask.request_class) -> (bool, int):
    cookies = flask_request.cookies
    if 'token' in cookies:
        token = cookies.get('token')
        cur = mysql.connection.cursor()
        cur.execute(
            'SELECT UserID FROM Session WHERE Token = %s',
            (token,))
        result = cur.fetchone()
        if 'UserID' in result:
            return True, result['UserID']
    return False, -1

# Route for landing page
@app.route("/")
def base():
    logged_in_as = is_logged_in(request)
    return render_template('base.html')

class SignupForm(Form):
    username = StringField('Username', [
        validators.DataRequired(),
        validators.Length(min=1, max=30)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')])
    confirm = PasswordField('Confirm password', [
        validators.DataRequired()])

# Route for sign up form

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    form = SignupForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        salt = urandom(16)
        password_hash = scrypt.hash(form.password.data, salt, 32768, 8, 1, 32)
        b64_salt = base64.b64encode(salt)
        b64_hash = base64.b64encode(password_hash)
        cur = mysql.connection.cursor()
        cur.execute(
            'INSERT INTO Users(UserName, PasswordHash, PasswordSalt) VALUES (%s, %s, %s)',
            (username, b64_hash, b64_salt))
        mysql.connection.commit()
        cur.close()
        return redirect(url_for('login'))
    return render_template('auth/signup.html', form=form)

class LoginForm(Form):
    username = StringField('Username', [
        validators.DataRequired(),
        validators.Length(min=1, max=30)])
    password = PasswordField('Password', [
        validators.DataRequired()])

# Route for sign up form
@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        cur = mysql.connection.cursor()
        cur.execute(
            'SELECT UserID, PasswordHash, PasswordSalt FROM Users WHERE UserName = %s',
            (username,))
        result = cur.fetchone()
        db_hash = base64.b64decode(result['PasswordHash'])
        salt = base64.b64decode(result['PasswordSalt'])
        password_hash = scrypt.hash(form.password.data, salt, 32768, 8, 1, 32)
        if password_hash == db_hash:
            token = base64.b64encode(urandom(64))
            user_id = result['UserID']
            cur.execute(
                'INSERT INTO Session(UserID, Token) VALUES (%s, %s)',
                (user_id, token))
            mysql.connection.commit()
            cur.close()
            resp = redirect(url_for('base'))
            resp.set_cookie(
                'token',
                token,
                86400,
                domain='127.0.0.1',
                # secure=True,
                httponly=True)
            return resp
    return render_template('auth/login.html', form=form)


    
# Route for workouts
@app.route("/workouts")
def workouts():
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM workouts")
    Workouts = cur.fetchall()

    if result > 0:
        return render_template('workouts.html', workouts=Workouts)
    else:
        msg = "No workouts Found"
        return render_template('workouts.html', msg=msg)
    cur.close()

    return render_template('workouts.html', workouts = Workouts)

@app.route("/workout/<string:id>/")
def workout(workoutID):
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM workouts WHERE id = %s," (workoutID))
    Workout = cur.fetchone()

    if result > 0:
        return render_template('workout.html', workout=Workout)
    else:
        msg = "No workouts Found"
        return render_template('workouts.html', msg=msg)
    cur.close()

    return render_template('workouts.html', workouts = Workout)




# Route for meals
@app.route("/meals")
def meals():
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM meals")
    Meals = cur.fetchall()

    if result > 0:
        return render_template('meals.html', meals=Meals)
    else:
        msg = "No workouts Found"
        return render_template('meals.html', msg=msg)
    cur.close()

    return render_template('meals.html', meals = Meals)

# Route for single meals
@app.route("/meal/<string:id>/")
def meal(mealID):
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM meals WHERE id = %s", (mealID))
    Meal = cur.fetchone()

    if result > 0:
        return render_template('meal.html', meal=Meal)
    else:
        msg = "No workouts Found"
        return render_template('meals.html', msg=msg)
    cur.close()

    return render_template('meals.html', meals = Meal)

# Route for trainers
@app.route("/trainers")
def trainers():
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM trainer")
    Trainers = cur.fetchall()

    if result > 0:
        return render_template('trainers.html', trainers=Trainers)
    else:
        msg = "No workouts Found"
        return render_template('trainers.html', msg=msg)
    cur.close()

    return render_template('trainers.html', trainers = Trainers)

# Route for single trainer
@app.route("/trainer/<string:id>/")
def trainer(trainerID):
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM trainer WHERE id = %s", (trainerID))
    Trainer = cur.fetchone()

    if result > 0:
        return render_template('trainer.html', trainer=Trainer)
    else:
        msg = "No workouts Found"
        return render_template('trainers.html', msg=msg)
    cur.close()

    return render_template('trainers.html', trainers = Trainer)


# Note: This is in debug mode. This means that it restarts with changes
if __name__ == "__main__":
    app.run(debug=True)

