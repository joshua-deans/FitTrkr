import base64
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
        if result is None:
            return False, -1
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
        if result is None:
            return False
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



# Route for about page
@app.route("/about/")
def about():
    return render_template('about.html')



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
        #Checks to see if username already exists
        cur = mysql.connect.cursor()
        username_check = cur.execute(
            'SELECT * from Users WHERE UserName = %s', [username, ]
        )
        cur.close()
        if username_check > 0:
           flash('Username is already taken, try a different one', 'danger')
           return render_template('auth/signup.html', form=form)
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

class SettingsForm(Form):
    first_name = StringField('First name', [
        validators.DataRequired(),
        validators.Length(min=1, max=30)
    ])
    last_name = StringField('Last name', [
        validators.DataRequired(),
        validators.Length(min=1, max=30)
    ])
    gender = StringField('Gender', [
        validators.DataRequired(),
        validators.Length(min=1, max=10)
    ])
    age = StringField('Age', [
        validators.DataRequired(),
        validators.Length(min=1, max=11)
    ])
    address = StringField('Address', [
        validators.DataRequired(),
        validators.Length(min=1, max=100)
    ])
    postal_code = StringField('Postal code', [
        validators.DataRequired(),
        validators.Length(min=1, max=6)
    ])
    city = StringField('City', [
        validators.DataRequired(),
        validators.Length(min=1, max=100)
    ])
    province_state = StringField('Province or State', [
        validators.DataRequired(),
        validators.Length(min=1, max=30)
    ])
    country = StringField('Country', [
        validators.DataRequired(),
        validators.Length(min=1, max=100)
    ])

@app.route("/settings/", methods=['GET', 'POST'])
def settings():
    form = SettingsForm(request.form)
    if is_logged_in_bool(request):
        user_id = is_logged_in(request)[1]
        if request.method == 'POST' and form.validate():
            cur = mysql.connection.cursor()
            cur.execute(
                'REPLACE INTO PostalCode(PostalCode, City, ProvinceState, Country) '
                'VALUES (%s, %s, %s, %s)',
                (form.postal_code.data,
                 form.city.data,
                 form.province_state.data,
                 form.country.data)
            )
            mysql.connection.commit()
            cur.execute(
                'UPDATE Users '
                'SET FirstName = %s, '
                'LastName = %s, '
                'Gender = %s, '
                'Age = %s, '
                'Address = %s, '
                'PostalCode = %s '
                'WHERE UserID = %s',
                (form.first_name.data,
                form.last_name.data,
                form.gender.data,
                form.age.data,
                form.address.data,
                form.postal_code.data,
                user_id)
            )
            mysql.connection.commit()
            cur.close()
            flash('Profile Updated!', 'success')
            return redirect(url_for('settings'))
        else:
            cur = mysql.connection.cursor()
            cur.execute(
                'SELECT * '
                'FROM Users '
                'WHERE UserID = %s',
                (user_id,)
            )
            res = cur.fetchone()
            city = None
            province_state = None
            country = None
            if 'PostalCode' in res:
                if cur.execute(
                    'SELECT City, ProvinceState, Country '
                    'FROM PostalCode '
                    'WHERE PostalCode = %s',
                    (res['PostalCode'],)
                ) > 0:
                    res_postal = cur.fetchone()
                    city = res_postal['City']
                    province_state = res_postal['ProvinceState']
                    country = res_postal['Country']
            cur.close()
            return render_template(
                'settings.html',
                form=form,
                first_name=res['FirstName'],
                last_name=res['LastName'],
                gender=res['Gender'],
                age=res['Age'],
                address=res['Address'],
                postal_code=res['PostalCode'],
                city=city,
                province_state=province_state,
                country=country
            )
    else:
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
        user_check = cur.execute(
            'SELECT UserID, PasswordHash, PasswordSalt FROM Users WHERE UserName = %s',
            (username,))
        result = cur.fetchone()
        if user_check >0:
            db_hash = base64.b64decode(result['PasswordHash'])
            salt = base64.b64decode(result['PasswordSalt'])
            password_hash = scrypt.hash(form.password.data, salt, 32768, 8, 1, 32)
            if password_hash == db_hash:
                app.logger.info('PASSWORD MATCHED')
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
                    # domain='127.0.0.1',
                    # secure=True,
                    httponly=True)
                flash('You are now logged in', 'success')
                return resp
            else:
                flash('Invalid Password, Try again', 'danger')
                app.logger.info('PASSWORD NOT MATCHED')
        else:
            flash('Invalid Username, Try again', 'danger')
            app.logger.info('NO USER')
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
    user_result = cur.fetchone()
    cur.close()
    if user_result:
        cur = mysql.connection.cursor()
        cur.execute(
            'SELECT f.FitnessProgramName, u1.UserName, u1.FirstName, u1.LastName, w.WorkoutPlanName, m.MealPlanName '
            'FROM Users u, FitnessProgram f, Clients c, Users u1, MealPlan m, WorkoutPlan w '
            'WHERE u.UserID = %s AND u.UserID = c.UserID AND c.Current_FitnessProgram = f.FitnessProgramID AND '
            'f.TrainerID = u1.UserID AND f.WorkoutPlanID = w.WorkoutPlanID AND f.MealPlanID = m.MealPlanID'
            , str(user_id))
        program_result = cur.fetchone()
        print(program_result)
        cur.close()
        return render_template('client/dashboard.html', user=user_result, fitness_program=program_result,
                               request=request, user_id=user_id)
    else:
        return redirect('/')


@app.route("/client/<int:user_id>/programs/")
def client_browse_plans(user_id, plan_info=None):
    # Browse all of the fitness plans
    cur = mysql.connection.cursor()
    cur.execute('SELECT COUNT(*) FROM FitnessProgram')
    count = cur.fetchone()['COUNT(*)']
    cur.execute(
        'SELECT f.FitnessProgramID, f.FitnessProgramName, u.FirstName, u.LastName, f.FP_intensity, f.Description, '
        'f.Program_Length, f.MealPlanID, f.WorkoutPlanID '
        'FROM FitnessProgram f, Users u WHERE f.TrainerID = u.UserID')
    result = cur.fetchall()
    cur.execute(
        'SELECT c.Current_FitnessProgram '
        'FROM Clients c, Users u WHERE c.UserID = u.UserID AND u.UserID = %s', str(user_id))
    curr_fitness_program = cur.fetchone()
    if result:
        plan_info = result
    cur.close()
    return render_template('client/browse_plans.html', plan_info=plan_info, user_id=user_id,
                           curr_fitness_program=curr_fitness_program, count=count)


@app.route("/client/<int:user_id>/change_program/<program_id>", methods=['POST'])
def client_change_plan(user_id, program_id):
    cur = mysql.connection.cursor()
    if program_id == "NULL":
        cur.execute(
            'UPDATE Clients c '
            'SET c.Current_FitnessProgram = NULL '
            'WHERE c.UserID = %s', (user_id,))
    else:
        cur.execute(
            'UPDATE Clients c '
            'SET c.Current_FitnessProgram = %s '
            'WHERE c.UserID = %s', (program_id, user_id))
    mysql.connection.commit()
    cur.close()
    return redirect(url_for('client_browse_plans', user_id=user_id))


@app.route("/client/<int:user_id>/logs/", methods=['GET', 'POST'])
def client_logs(user_id, log_info=None):
    # Browse all of the fitness plans
    cur = mysql.connection.cursor()
    cur.execute(
        'SELECT l.LogID, f.FitnessProgramName, l.LogDate, l.Weight, l.WorkoutCompletion, l.Notes, l.SatisfactionLevel, '
        'l.MealCompletion FROM FitnessProgram f, Logs l, Users u WHERE l.UserID = u.UserID AND '
        'l.FitnessProgramID = f.FitnessProgramID AND u.UserID = %s ', str(user_id))
    result = cur.fetchall()
    print(result)
    if result:
        log_info = result
    cur.execute("SELECT c.Current_FitnessProgram FROM Clients c WHERE c.UserID = %s", (user_id,))
    current_fitness_program = cur.fetchone()
    cur.close()
    if request.method == 'POST':
        log_date = request.form.get('log-date')
        weight = request.form.get('weight')
        workout_completion = request.form.get('workout-completion')
        meal_completion = request.form.get('meal-completion')
        satisfaction = request.form.get('satisfaction')
        notes = request.form.get('notes')
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO Logs(UserID, FitnessProgramID, LogDate, Weight, WorkoutCompletion, Notes, "
                    "SatisfactionLevel, MealCompletion) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                    (user_id, current_fitness_program['Current_FitnessProgram'], log_date, weight, workout_completion,
                     notes, satisfaction, meal_completion))
        mysql.connection.commit()
        cur.close()
        flash('New Log Created! Way To Go!', 'success')
        return redirect(url_for('client_logs', user_id=user_id))
    else:
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
        return render_template('client/client_logs.html', log_info=log_info, user_id=user_id,
                               current_fitness_program=current_fitness_program)

#Delete Log

@app.route('/delete_log/<string:logid>', methods=['POST'])
def delete_log(logid):
    #Create Cursor
    cur = mysql.connection.cursor()
    #Store userid
    user_id = cur.execute("select userid FROM logs where logid=%s", [str(logid)])
    result = cur.fetchone()
    cur.close()
    #Delete Log
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM logs where logid= %s", [str(logid)])

    mysql.connection.commit()
    cur.close()
    flash('Log Deleted! Go Make Another One!', 'success')
    return redirect(url_for('client_logs', user_id=user_id))

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
def trainer_all_plans(user_id, plan_info=None):
    # All fitness plans made by all of the trainers
    cur = mysql.connection.cursor()
    cur.execute('SELECT COUNT(*) FROM FitnessProgram f, Users u WHERE f.TrainerID = u.UserID')
    count = cur.fetchone()['COUNT(*)']
    cur.execute(
        'SELECT f.FitnessProgramID, u.FirstName, u.LastName, f.FP_intensity, f.Description, f.Program_Length, '
        'f.MealPlanID, f.WorkoutPlanID '
        'FROM FitnessProgram f, Users u WHERE f.TrainerID = u.UserID')
    result = cur.fetchall()
    if result:
        plan_info = result
    cur.close()
    return render_template('trainer/browse_plans.html', plan_info=plan_info, user_id=user_id, count=count)


@app.route("/trainer/<int:user_id>/programs/", methods=['GET', 'POST'])
def trainer_plans(user_id):
    # Only the fitness plans made by the trainer
    if request.method == 'POST':
        program_name = request.form.get('program-name')
        program_intensity = request.form.get('program-intensity')
        program_length = request.form.get('program-length')
        workout_plan = request.form.get('workout-plan')
        meal_plan = request.form.get('meal-plan')
        program_description = request.form.get('program-description')
        workout_plan_id = workout_plan[0:workout_plan.find('.')]
        meal_plan_id = meal_plan[0:meal_plan.find('.')]
        cur = mysql.connection.cursor()
        cur.execute(
            'INSERT INTO FitnessProgram(FitnessProgramName, FP_intensity, Description, Program_Length, TrainerID, '
            'WorkoutPlanID, MealPlanID) VALUES (%s, %s, %s, %s, %s, %s, %s)', (program_name, program_intensity,
                                                                               program_description, program_length,
                                                                               str(user_id), workout_plan_id,
                                                                               meal_plan_id))
        mysql.connection.commit()
        cur.close()
        return redirect(url_for('trainer_plans', user_id=user_id))
    else:
        cur = mysql.connection.cursor()
        cur.execute(
            'SELECT f.FitnessProgramID, u.FirstName, u.LastName, f.FP_intensity, f.Description, f.Program_Length, '
            'f.MealPlanID, f.WorkoutPlanID '
            'FROM FitnessProgram f, Users u WHERE f.TrainerID = u.UserID AND u.UserID = %s', str(user_id))
        result = cur.fetchall()
        cur.execute(
            'SELECT * '
            'FROM MealPlan m')
        meal_plans = cur.fetchall()
        cur.execute(
            'SELECT * '
            'FROM WorkoutPlan w')
        workout_plans = cur.fetchall()
        if result:
            plan_info = result
        cur.close()
        return render_template('trainer/trainer_plans.html', plan_info=plan_info, user_id=user_id,
                               meal_plans=meal_plans,
                               workout_plans=workout_plans)


@app.route("/trainer/<int:user_id>/meal_plans/")
def trainer_meal_plans(user_id):
    # Only the meal plans made by the trainer
    cur = mysql.connection.cursor()
    cur.execute(
        'SELECT m.MealPlanID, m.Category, m.DietaryRestrictions, m.MealPlanDescription, '
        'f.FitnessProgramID FROM FitnessProgram f, MealPlan m, Users u WHERE f.TrainerID = u.UserID AND '
        'm.MealPlanID = f.MealPlanID AND u.UserID = %s', str(user_id))
    result = cur.fetchall()
    print(result)
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
        # Get Form Fields
        WorkoutName = request.form['WorkoutName']
        WorkoutNamePassed = '%' + WorkoutName + '%'
        cur = mysql.connection.cursor()
        cur.execute('SELECT COUNT(*) FROM Workouts WHERE WorkoutName LIKE %s ', [WorkoutNamePassed])
        count = cur.fetchone()['COUNT(*)']
        result = cur.execute("SELECT * FROM Workouts WHERE WorkoutName LIKE %s ", [WorkoutNamePassed])
        Workouts = cur.fetchall()
        cur.close()

        if result > 0:
            return render_template('workouts.html', workouts=Workouts, count=count)
        else:
            msg = "No workouts Found"
            return render_template('workouts.html', msg=msg)

    else:
        cur = mysql.connection.cursor()
        cur.execute('SELECT COUNT(*) FROM Workouts')
        count = cur.fetchone()['COUNT(*)']
        result = cur.execute("SELECT * FROM Workouts")
        Workouts = cur.fetchall()
        cur.close()

        if result > 0:
            return render_template('workouts.html', workouts=Workouts, count=count)
        else:
            msg = "No workouts Found"
            return render_template('workouts.html', msg=msg)



# Route for adding strength workouts
@app.route("/add_strength_workout", methods=['POST'])
def add_strength_workout():
    if request.method == 'POST':
        # Get Form Fields
        workout_name = request.form.get('strength-workout-name')
        workout_intensity = request.form.get('strength-workout-intensity')
        workout_equipment = request.form.get('strength-workout-equipment')
        workout_body_part = request.form.get('strength-body-part')
        workout_strength_type = request.form.get('strength-type')
        workout_description = request.form.get('strength-workout-description')
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO Workouts(Intensity, WorkoutDescription, Equipment, WorkoutName) "
                    "VALUES (%s, %s, %s, %s)",
                    (workout_intensity, workout_description, workout_equipment, workout_name))
        cur.execute("INSERT INTO Strength(WorkoutID, BodyPart, StrengthType) "
                    "VALUES (%s, %s, %s)",
                    (cur.lastrowid, workout_body_part, workout_strength_type))
        mysql.connection.commit()
        cur.close()

        return redirect(url_for('workouts'))


# Route for adding cardio workouts
@app.route("/add_cardio_workout", methods=['POST'])
def add_cardio_workout():
    if request.method == 'POST':
        # Get Form Fields
        workout_name = request.form.get('cardio-workout-name')
        workout_intensity = request.form.get('cardio-workout-intensity')
        workout_equipment = request.form.get('cardio-workout-equipment')
        workout_distance = request.form.get('cardio-distance')
        workout_duration = request.form.get('cardio-duration')
        cardio_type = request.form.get('cardio-workout-type')
        workout_description = request.form.get('cardio-workout-description')
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO Workouts(Intensity, WorkoutDescription, Equipment, WorkoutName) "
                    "VALUES (%s, %s, %s, %s)",
                    (workout_intensity, workout_description, workout_equipment, workout_name))
        cur.execute("INSERT INTO Cardio(WorkoutID, Distance, Duration, CardioType) "
                    "VALUES (%s, %s, %s, %s)",
                    (cur.lastrowid, workout_distance, workout_duration, cardio_type))
        mysql.connection.commit()
        cur.close()

        return redirect(url_for('workouts'))


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



# Route for meals
@app.route("/meals/", methods=['GET', 'POST'])
def meals():
    if request.method == 'POST':
        # Get Form Fields
        MealName = request.form['MealName']
        MealNamePassed = '%' + MealName + '%'
        cur = mysql.connection.cursor()
        cur.execute('SELECT COUNT(*) FROM Meals WHERE MealName LIKE %s ', [MealNamePassed])
        count = cur.fetchone()['COUNT(*)']
        result = cur.execute("SELECT * FROM Meals WHERE MealName LIKE %s ", [MealNamePassed])
        Meals = cur.fetchall()
        cur.close()

        if result > 0:
            return render_template('meals.html', meals=Meals, count=count)
        else:
            msg = "No meals Found"
            return render_template('meals.html', msg=msg)

    else:
        cur = mysql.connection.cursor()
        cur.execute('SELECT COUNT(*) FROM Meals')
        count = cur.fetchone()['COUNT(*)']
        result = cur.execute("SELECT * FROM Meals")
        Meals = cur.fetchall()
        cur.close()

        if result > 0:
            return render_template('meals.html', meals=Meals, count=count)
        else:
            msg = "No meals Found"
            return render_template('meals.html', msg=msg)



# Route for adding meals
@app.route("/add_meal", methods=['POST'])
def add_meal():
    if request.method == 'POST':
        # Get Form Fields
        meal_name = request.form.get('meal-name')
        meal_type = request.form.get('meal-type')
        calories = request.form.get('calories')
        dietary_restrictions = request.form.get('dietary-restrictions')
        meal_description = request.form.get('meal-description')
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO Meals(MealName, MealType, CaloriesPerServing, DietaryRestrictions, MealDescription) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (meal_name, meal_type, calories, dietary_restrictions, meal_description))
        mysql.connection.commit()
        cur.close()

        return redirect(url_for('meals'))


# Route for single meals
@app.route("/meal/<string:mealID>/")
def meal(mealID):
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM Meals WHERE MealID = %s", (mealID,))
    ret_meal = cur.fetchone()
    cur.close()

    if result > 0:
        return render_template('meal.html', meal=ret_meal)
    else:
        msg = "No meals Found"
        return render_template('meals.html', msg=msg)



# Route for trainers
@app.route("/trainers_search", methods=['GET', 'POST'])
def trainers_search():
    if request.method == 'POST':
        # Get Form Fields
        TrainerUserName = request.form['UserName']
        TrainerUserNamePassed = '%' + TrainerUserName + '%'
        cur = mysql.connection.cursor()
        cur.execute('SELECT COUNT(*) FROM Users u, Trainers t WHERE u.UserID = t.UserID AND u.UserName LIKE %s ',
                    [TrainerUserNamePassed])
        count = cur.fetchone()['COUNT(*)']
        result = cur.execute("SELECT * FROM Users u, Trainers t WHERE u.UserID = t.UserID AND u.UserName LIKE %s ",
                             [TrainerUserNamePassed])
        Trainers = cur.fetchall()

        cur.close()
        if result > 0:
            return render_template('trainers.html', trainers=Trainers, count=count)
        else:
            msg = "No trainers Found"
            return render_template('trainers.html', msg=msg)

    else:
        cur = mysql.connection.cursor()
        cur.execute('SELECT COUNT(*) FROM Users u, Trainers t WHERE u.UserID = t.UserID')
        count = cur.fetchone()['COUNT(*)']
        result = cur.execute(
            'SELECT * FROM Users u, Trainers t WHERE u.UserID = t.UserID')
        Trainers = cur.fetchall()
        cur.close()

        if result > 0:
            return render_template('trainers.html', trainers=Trainers, count=count)
        else:
            msg = "No trainers Found"
            return render_template('trainers.html', msg=msg)



# Route for single trainer
@app.route("/trainer_search/<string:UserID>/")
def trainer_search(UserID):
    cur = mysql.connection.cursor()
    print(UserID)
    result = cur.execute('SELECT *'
                         'FROM Trainers AS t INNER JOIN Users AS u ON u.UserID = t.UserID WHERE u.UserID = %s AND t.UserID=%s',
                         (UserID, UserID))
    Trainer = cur.fetchone()
    cur.close()

    if result > 0:
        return render_template('trainer.html', trainer=Trainer)
    else:
        msg = "No trainers Found"
        return render_template('trainers.html', msg=msg)



# Note: This is in debug mode. This means that it restarts with changes
if __name__ == "__main__":
    app.secret_key = 'secret123'
    app.run(debug=True)
