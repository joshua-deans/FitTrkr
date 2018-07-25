import base64
from datetime import datetime
from os import urandom

import scrypt
from flask import Flask, render_template, url_for, request, redirect, flash
from flask_mysqldb import MySQL
from wtforms import Form, StringField, PasswordField, validators

from db import DBconfig

app = Flask(__name__)

DBconfig = DBconfig()

# Configure DB
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

def is_logged_in_bool(flask_request: Flask.request_class) -> bool:
    cookies = flask_request.cookies
    if 'token' in cookies:
        token = cookies.get('token')
        cur = mysql.connection.cursor()
        cur.execute(
            'SELECT UserID FROM Session WHERE Token = %s',
            (token,))
        result = cur.fetchone()
        if 'UserID' in result:
            return True
    return False

app.jinja_env.globals.update(is_logged_in_bool=is_logged_in_bool)

def verify_proper_user(logged_in_as, user_id):
    if not logged_in_as[0]:
        return False
    if logged_in_as[1] != user_id:
        return False
    else:
        return True


# Route for landing page
@app.route("/")
def base():
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

@app.route("/signup/", methods=['GET', 'POST'])
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
        flash('You are now registered and can log in', 'success')
        return redirect(url_for('login'))
    return render_template('auth/signup.html', form=form)

@app.route("/settings/", methods=['GET', 'POST'])
def settings():
    return redirect(url_for('base'))

class LoginForm(Form):
    username = StringField('Username', [
        validators.DataRequired(),
        validators.Length(min=1, max=30)])
    password = PasswordField('Password', [
        validators.DataRequired()])


# Route for sign up form
@app.route("/login/", methods=['GET', 'POST'])
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
            flash('You are now logged in', 'success')
            return resp
    return render_template('auth/login.html', form=form)

@app.route("/logout/")
def logout():
    resp = redirect(url_for('base'))
    if is_logged_in(request)[0]:
        cur = mysql.connection.cursor()
        cur.execute(
            'DELETE FROM Session WHERE Token = %s',
            (request.cookies.get('token'),))
        mysql.connection.commit()
        cur.close()
        resp.set_cookie(
            'token',
            '',
            expires='Thu, 01 Jan 1970 00:00:00 GMT'
        )
    return resp

# CLIENT ROUTES


@app.route("/client/<int:user_id>/")
def client(user_id):
    cur = mysql.connection.cursor()
    cur.execute(
        'SELECT * '
        'FROM Users u WHERE u.UserID = %s AND u.UserID IN (SELECT UserID FROM Clients)', str(user_id))
    result = cur.fetchone()
    cur.close()
    if result:
        return render_template('client/dashboard.html', user=result, request=request, user_id=user_id)
    else:
        return redirect('/')


@app.route("/client/<int:user_id>/programs/")
def client_browse_plans(user_id, plan_info=None):
    # Browse all of the fitness plans
    cur = mysql.connection.cursor()
    cur.execute(
        'SELECT f.FitnessProgramID, u.FirstName, u.LastName, f.FP_intensity, f.Description, f.Program_Length, '
        'f.MealPlanID, f.WorkoutPlanID '
        'FROM FitnessProgram f, Users u WHERE f.TrainerID = u.UserID')
    result = cur.fetchall()
    if result:
        plan_info = result
    cur.close()
    return render_template('client/browse_plans.html', plan_info=plan_info, user_id=user_id)


@app.route("/client/<int:user_id>/logs/")
def client_logs(user_id, log_info=None):
    # Browse all of the fitness plans
    cur = mysql.connection.cursor()
    cur.execute(
        'SELECT l.LogID, f.FitnessProgramID, l.LogDate, l.Weight, l.WorkoutCompletion, l.Notes, l.SatisfactionLevel, '
        'l.MealCompletion FROM FitnessProgram f, Logs l, Users u WHERE l.UserID = u.UserID AND '
        'l.FitnessProgramID = f.FitnessProgramID AND u.UserID = %s', str(user_id))
    result = cur.fetchall()
    print(result)
    if result:
        log_info = result
    cur.close()
    return render_template('client/client_logs.html', log_info=log_info, user_id=user_id)


# TRAINER ROUTES


@app.route("/trainer/<int:user_id>/")
def trainer(user_id):
    cur = mysql.connection.cursor()
    cur.execute(
        'SELECT * '
        'FROM Users u WHERE u.UserID = %s AND u.UserID IN (SELECT UserID FROM Trainers)', str(user_id))
    result = cur.fetchone()
    cur.close()
    if result:
        return render_template('trainer/dashboard.html', user=result, user_id=user_id)
    else:
        return redirect('/')


@app.route("/trainer/<int:user_id>/all_programs/")
def trainer_all_plans(user_id):
    # All fitness plans made by all of the trainers
    cur = mysql.connection.cursor()
    cur.execute(
        'SELECT f.FitnessProgramID, u.FirstName, u.LastName, f.FP_intensity, f.Description, f.Program_Length, '
        'f.MealPlanID, f.WorkoutPlanID '
        'FROM FitnessProgram f, Users u WHERE f.TrainerID = u.UserID')
    result = cur.fetchall()
    if result:
        plan_info = result
    cur.close()
    return render_template('trainer/browse_plans.html', plan_info=plan_info, user_id=user_id)


@app.route("/trainer/<int:user_id>/programs/")
def trainer_plans(user_id):
    # Only the fitness plans made by the trainer
    cur = mysql.connection.cursor()
    cur.execute(
        'SELECT f.FitnessProgramID, u.FirstName, u.LastName, f.FP_intensity, f.Description, f.Program_Length, '
        'f.MealPlanID, f.WorkoutPlanID '
        'FROM FitnessProgram f, Users u WHERE f.TrainerID = u.UserID AND u.UserID = %s', str(user_id))
    result = cur.fetchall()
    if result:
        plan_info = result
    cur.close()
    return render_template('trainer/browse_plans.html', plan_info=plan_info, user_id=user_id)


@app.route("/trainer/<int:user_id>/meal_plans/")
def trainer_meal_plans(user_id):
    # Only the meal plans made by the trainer
    cur = mysql.connection.cursor()
    cur.execute(
        'SELECT m.MealPlanID, m.Category, m.DietaryRestrictions, m.MealPlanDescription, '
        'f.FitnessProgramID FROM FitnessProgram f, MealPlan m, Users u WHERE f.TrainerID = u.UserID AND '
        'm.MealPlanID = f.MealPlanID AND u.UserID = %s', str(user_id))
    result = cur.fetchall()
    print(result);
    if result:
        plan_info = result
    cur.close()
    return render_template('trainer/meal_plans.html', meal_plan_info=plan_info, user_id=user_id)


@app.route("/trainer/<int:user_id>/workout_plans/")
def trainer_workout_plans(user_id):
    # Only the meal plans made by the trainer
    cur = mysql.connection.cursor()
    cur.execute(
        'SELECT w.WorkoutPlanID, w.Intensity, w.PlanDescription, '
        'f.FitnessProgramID FROM FitnessProgram f, WorkoutPlan w, Users u WHERE f.TrainerID = u.UserID AND '
        'w.WorkoutPlanID = f.WorkoutPlanID AND u.UserID = %s', str(user_id))
    result = cur.fetchall()
    if result:
        plan_info = result
    cur.close()
    return render_template('trainer/workout_plans.html', workout_plan_info=plan_info, user_id=user_id)


# Route for workouts
@app.route("/workouts", methods=['GET', 'POST'])
def workouts():
    if request.method == 'POST':
        #Get Form Fields
        WorkoutName = request.form['WorkoutName']
        WorkoutNamePassed = '%' + WorkoutName + '%' 
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM Workouts WHERE WorkoutName LIKE %s ", [WorkoutNamePassed])
        Workouts = cur.fetchall()

        if result > 0:
            return render_template('workouts.html', workouts=Workouts)
        else:
            msg = "No meals Found"
            return render_template('workouts.html', msg=msg)
        cur.close()

    else: 
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM Workouts")
        Workouts = cur.fetchall()

        if result > 0:
            return render_template('workouts.html', workouts=Workouts)
        else:
            msg = "No workouts Found"
            return render_template('workouts.html', msg=msg)
        cur.close()

    return render_template('workouts.html', workouts=Workouts)


@app.route("/workout/<string:workoutID>/")
def workout(workoutID):
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM Workouts WHERE WorkoutID = %s", (workoutID))
    Workout = cur.fetchone()
    cur.close()
    if result > 0:
        return render_template('workout.html', workout=Workout)
    else:
        msg = "No workouts Found"
        return render_template('workouts.html', msg=msg)

    return render_template('workouts.html', workouts=Workout)


# Route for meals
@app.route("/meals/", methods=['GET', 'POST'])
def meals():
    if request.method == 'POST':
        #Get Form Fields
        MealName = request.form['MealName']
        MealNamePassed = '%' + MealName + '%' 
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM Meals WHERE MealName LIKE %s ", [MealNamePassed])
        Meals = cur.fetchall()

        if result > 0:
            return render_template('meals.html', meals=Meals)
        else:
            msg = "No meals Found"
            return render_template('meals.html', msg=msg)
        cur.close()

    else: 
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM Meals")
        Meals = cur.fetchall()

        if result > 0:
            return render_template('meals.html', meals=Meals)
        else:
            msg = "No workouts Found"
            return render_template('meals.html', msg=msg)
        cur.close()

    return render_template('meals.html', meals=Meals)


# Route for single meals
@app.route("/meal/<string:mealID>/")
def meal(mealID):
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM Meals WHERE MealID = %s", (mealID))
    Meal = cur.fetchone()

    if result > 0:
        return render_template('meal.html', meal=Meal)
    else:
        msg = "No workouts Found"
        return render_template('meals.html', msg=msg)
    cur.close()

    return render_template('meals.html', meals=Meal)


# Route for trainers
@app.route("/trainers_search", methods=['GET', 'POST'])
def trainers_search():
    if request.method == 'POST':
        #Get Form Fields
        TrainerUserName = request.form['UserName']
        TrainerUserNamePassed = '%' + TrainerUserName + '%' 
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM Users u, Trainers t WHERE u.UserID = t.UserID AND u.UserName LIKE %s " , [TrainerUserNamePassed] )
        Trainers = cur.fetchall()

        if result > 0:
            return render_template('trainers.html', trainers=Trainers)
        else:
            msg = "No meals Found"
            return render_template('trainers.html', msg=msg)
        cur.close()

    else: 
        cur = mysql.connection.cursor()
        result = cur.execute(
            'SELECT * FROM Users u, Trainers t WHERE u.UserID = t.UserID')
        Trainers = cur.fetchall()

        if result > 0:
            return render_template('trainers.html', trainers=Trainers)
        else:
            msg = "No workouts Found"
            return render_template('trainers.html', msg=msg)
        cur.close()

    return render_template('trainers.html', trainers=Trainers)


# Route for single trainer
@app.route("/trainer_search/<string:UserID>/")
def trainer_search(UserID):
    cur = mysql.connection.cursor()
    # userid = str(UserID)
    # userid4 = "13"
    # #print(userid4)
    # result = cur.execute('SELECT t.UserID, UserName, FirstName, LastName, TrainerFocus t.trainerFoc FROM trainers t, users u'
    #                     'WHERE t.UserID = u.UserID AND t.UserID = %s', str(UserID) )
    print(UserID)
    result = cur.execute('SELECT *'
                        'FROM Trainers AS t INNER JOIN Users AS u ON u.UserID = t.UserID WHERE u.UserID = %s AND t.UserID=%s', (UserID,UserID) )
    Trainer = cur.fetchone()

    if result > 0:
        return render_template('trainer.html', trainer=Trainer)
    else:
        msg = "No workouts Found"
        return render_template('trainers.html', msg=msg)
    cur.close()

    return render_template('trainers.html', trainers=Trainer)


# Note: This is in debug mode. This means that it restarts with changes
if __name__ == "__main__":
    app.secret_key = 'secret123'
    app.run(debug=True)
