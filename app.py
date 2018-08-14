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

def is_logged_in_userid(flask_request: Flask.request_class) -> int:
    cookies = flask_request.cookies
    if 'token' in cookies:
        token = cookies.get('token')
        cur = mysql.connection.cursor()
        cur.execute(
            'SELECT UserID FROM Session WHERE Token = %s',
            (token,))
        result = cur.fetchone()
        if result is None:
            return -1
        if 'UserID' in result:
            return result['UserID']
    return -1

app.jinja_env.globals.update(is_logged_in_bool=is_logged_in_bool)
app.jinja_env.globals.update(is_logged_in_userid=is_logged_in_userid)


def verify_proper_user(logged_in_as, user_id):
    if not logged_in_as[0]:
        return False
    if logged_in_as[1] != user_id:
        return False
    else:
        return True


def get_trainer_or_client(user_id):
    cur = mysql.connect.cursor()
    client_check = cur.execute(
        'SELECT * from Clients WHERE UserId = %s', [user_id]
    )
    trainer_check = cur.execute(
        'SELECT * from Trainers WHERE UserId = %s', [user_id]
    )
    cur.close()
    if client_check > 0:
        return 'client'
    elif trainer_check > 0:
        return 'trainer'

app.jinja_env.globals.update(get_trainer_or_client=get_trainer_or_client)



def check_if_ids_match(url_user_id, current_user_id):
    if url_user_id == current_user_id:
        return None
    else:
        trainer_or_client = get_trainer_or_client(current_user_id)
        if trainer_or_client == 'trainer':
            resp = redirect(url_for('trainer', user_id=current_user_id))
        elif trainer_or_client == 'client':
            resp = redirect(url_for('client', user_id=current_user_id))
        return resp


def ensure_user_is_not_logged_in():
    logged_in = is_logged_in(request)
    trainer_or_client = get_trainer_or_client(logged_in[1])
    if logged_in[0]:
        if trainer_or_client == 'trainer':
            resp = redirect(url_for('trainer', user_id=logged_in[1]))
        elif trainer_or_client == 'client':
            resp = redirect(url_for('client', user_id=logged_in[1]))
        else:
            resp = render_template('base.html')
    else:
        resp = None
    return resp


def ensure_user_is_logged_in_properly(url_user_id):
    logged_in = is_logged_in(request)
    current_user_id = logged_in[1]
    trainer_or_client = get_trainer_or_client(current_user_id)
    if not logged_in[0]:
        resp = render_template('base.html')
        return resp
    elif current_user_id != url_user_id:
        if trainer_or_client == 'trainer':
            resp = redirect(url_for('trainer', user_id=current_user_id))
        elif trainer_or_client == 'client':
            resp = redirect(url_for('client', user_id=current_user_id))
        else:
            resp = render_template('base.html')
        return resp
    else:
        return None


# Route for landing page
@app.route("/")
def base():
    redir = ensure_user_is_not_logged_in()
    if redir:
        return redir
    return render_template('base.html')


# Route for about page
@app.route("/about/")
def about():
    redir = ensure_user_is_not_logged_in()
    if redir:
        return redir
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
    firstname = StringField('First Name', [
        validators.DataRequired(),
        validators.Length(min=1, max=30)])
    lastname = StringField('Last Name', [
        validators.DataRequired(),
        validators.Length(min=1, max=30)])

# Route for sign up form

@app.route("/signup/", methods=['GET', 'POST'])
def signup():
    redir = ensure_user_is_not_logged_in()
    if redir:
        return redir
    form = SignupForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        firstname = form.firstname.data
        lastname = form.lastname.data
        client_trainer_option = request.form['trainer_client_radio']
        # Checks to see if username already exists
        cur = mysql.connect.cursor()
        username_check = cur.execute(
            'SELECT * from Users WHERE UserName = %s', [username]
        )
        cur.close()
        if username_check > 0:
            flash('Username is already taken, try a different one', 'danger')
            return render_template('auth/signup.html', form=form)
        if username_check > 0 or (not client_trainer_option):
            flash('Username is already taken, try a different one', 'danger')
            return render_template('auth/signup.html', form=form)
        salt = urandom(16)
        password_hash = scrypt.hash(form.password.data, salt, 32768, 8, 1, 32)
        b64_salt = base64.b64encode(salt)
        b64_hash = base64.b64encode(password_hash)
        cur = mysql.connection.cursor()
        cur.execute(
            'INSERT INTO Users(UserName,Firstname, Lastname, PasswordHash, PasswordSalt) VALUES (%s,%s,%s, %s, %s)',
            (username, firstname, lastname, b64_hash, b64_salt))
        if client_trainer_option == 'trainer':
            cur.execute(
                'INSERT INTO Trainers(UserID) VALUES (%s)',
                (cur.lastrowid,))
            mysql.connection.commit()
            cur.close()
        elif client_trainer_option == 'client':
            cur.execute(
                'INSERT INTO Clients(UserID) VALUES (%s)',
                (cur.lastrowid,))
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
        validators.Length(min=1, max=11),
        validators.Regexp('^[0-9]*$', message='Please enter an integer')
    ])
    address = StringField('Address', [
        validators.DataRequired(),
        validators.Length(min=1, max=100)
    ])
    postal_code = StringField('Postal code', [
        validators.DataRequired(),
        validators.Length(min=1, max=6, message='No More than 6 CHAR')
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
            num_entries = cur.execute(
                'SELECT * '
                'FROM PostalCode '
                'WHERE PostalCode = %s',
                (form.postal_code.data,)
            )
            if num_entries > 0:
                cur.execute(
                    'UPDATE PostalCode '
                    'SET City = %s, ProvinceState = %s, Country = %s '
                    'WHERE PostalCode = %s',
                    (form.city.data,
                     form.province_state.data,
                     form.country.data,
                     form.postal_code.data)
                )
            else:
                cur.execute(
                    'INSERT INTO PostalCode(PostalCode, City, ProvinceState, Country) '
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
            trainer_or_client = get_trainer_or_client(user_id)
            if trainer_or_client == 'client':
                client = True
            else:
                client = False
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
                country=country,
                user_id=is_logged_in(request)[1],
                client=client
            )
    else:
        return redirect(url_for('base'))


class LoginForm(Form):
    username = StringField('Username', [
        validators.DataRequired(),
        validators.Length(min=1, max=30)])
    password = PasswordField('Password', [
        validators.DataRequired()])


@app.route("/delete/<int:user_id>", methods=['POST'])
def delete_self(user_id):
    cur = mysql.connection.cursor()
    delete_user = cur.execute(
        'DELETE FROM Users WHERE UserID = %s',
        (user_id,))
    mysql.connection.commit()
    if delete_user:
        flash('Success! Your account was deleted.', 'success')
        return redirect(url_for('logout'))
    else:
        flash('Error! Your account could not be deleted!', 'error')
        return redirect(url_for('settings'))


# Route for sign up form
@app.route("/login/", methods=['GET', 'POST'])
def login():
    redir = ensure_user_is_not_logged_in()
    if redir:
        return redir
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        cur = mysql.connection.cursor()
        user_check = cur.execute(
            'SELECT UserID, PasswordHash, PasswordSalt FROM Users WHERE UserName = %s',
            (username,))
        result = cur.fetchone()
        if user_check > 0:
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
                trainer_or_client = get_trainer_or_client(user_id)
                if trainer_or_client == 'trainer':
                    resp = redirect(url_for('trainer', user_id=user_id))
                elif trainer_or_client == 'client':
                    resp = redirect(url_for('client', user_id=user_id))
                else:
                    resp = redirect(url_for('login'))
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
    redir = ensure_user_is_logged_in_properly(user_id)
    if redir:
        return redir
    cur = mysql.connection.cursor()
    cur.execute(
        'SELECT * '
        'FROM Users u WHERE u.UserID = %s AND u.UserID IN (SELECT UserID FROM Clients)', (user_id,))
    user_result = cur.fetchone()
    cur.close()
    if user_result:
        cur = mysql.connection.cursor()
        cur.execute(
            'SELECT f.FitnessProgramName, u1.UserName, u1.FirstName, u1.LastName, w.WorkoutPlanName, m.MealPlanName '
            'FROM Users u, FitnessProgram f, Clients c, Users u1, MealPlan m, WorkoutPlan w '
            'WHERE u.UserID = %s AND u.UserID = c.UserID AND c.Current_FitnessProgram = f.FitnessProgramID AND '
            'f.TrainerID = u1.UserID AND f.WorkoutPlanID = w.WorkoutPlanID AND f.MealPlanID = m.MealPlanID'
            , (user_id,))
        program_result = cur.fetchone()
        print(program_result)
        cur.close()
        return render_template('client/dashboard.html', user=user_result, fitness_program=program_result,
                               request=request, user_id=user_id)
    else:
        return redirect('/')


# @app.route("/client/<int:user_id>/program_detail/")
# def client_browse_plan_detail(user_id, plan_info=None):
#     # Browse all of the fitness plans
#     redir = ensure_user_is_logged_in_properly(user_id)
#     if redir:
#         return redir
#     cur = mysql.connection.cursor()
#     cur.execute('SELECT COUNT(*) FROM FitnessProgram')
#     count = cur.fetchone()['COUNT(*)']
#     cur.execute(
#         'SELECT f.FitnessProgramID, f.FitnessProgramName, u.FirstName, u.LastName, f.FP_intensity, f.Description, '
#         'f.Program_Length, f.MealPlanID, f.WorkoutPlanID '
#         'FROM FitnessProgram f, Users u WHERE f.TrainerID = u.UserID')
#     result = cur.fetchall()
#     cur.execute(
#         'SELECT c.Current_FitnessProgram '
#         'FROM Clients c, Users u WHERE c.UserID = u.UserID AND u.UserID = %s', (user_id,))
#     curr_fitness_program = cur.fetchone()
#
#     plan_info = result
#     cur.close()
#     return render_template('client/browse_plans.html', plan_info=plan_info, user_id=user_id,
#                            curr_fitness_program=curr_fitness_program, count=count)


@app.route("/client/<int:user_id>/programs/")
def client_browse_plans(user_id, plan_info=None):
    # Browse all of the fitness plans
    redir = ensure_user_is_logged_in_properly(user_id)
    if redir:
        return redir
    cur = mysql.connection.cursor()
    cur.execute('SELECT COUNT(*) FROM FitnessProgram')
    count = cur.fetchone()['COUNT(*)']
    cur.execute(
        'SELECT f.FitnessProgramID, f.FitnessProgramName, u.FirstName, u.LastName, u.UserName, f.FP_intensity, f.Description, '
        'f.Program_Length, f.MealPlanID, f.WorkoutPlanID '
        'FROM FitnessProgram f, Users u WHERE f.TrainerID = u.UserID')
    result = cur.fetchall()
    cur.execute(
        'SELECT c.Current_FitnessProgram '
        'FROM Clients c, Users u WHERE c.UserID = u.UserID AND u.UserID = %s', (user_id,))
    curr_fitness_program = cur.fetchone()

    plan_info = result
    cur.close()
    return render_template('client/browse_plans.html', plan_info=plan_info, user_id=user_id,
                           curr_fitness_program=curr_fitness_program, count=count)


@app.route("/client/<int:user_id>/current_program/")
def client_current_plan(user_id):
    # Browse all of the fitness plans
    redir = ensure_user_is_logged_in_properly(user_id)
    if redir:
        return redir
    cur = mysql.connection.cursor()
    cur.execute('SELECT f.FitnessProgramID FROM Clients c, FitnessProgram f '
                'WHERE c.UserID = %s AND c.Current_FitnessProgram = f.FitnessProgramID', (user_id,))
    result = cur.fetchone()
    cur.close()
    if result:
        return redirect(url_for('client_plan_details', user_id=user_id, program_id=result['FitnessProgramID']))
    else:
        return redirect(url_for('base'))


@app.route("/client/<int:user_id>/program/<int:program_id>")
def client_plan_details(user_id, program_id):
    redir = ensure_user_is_logged_in_properly(user_id)
    if redir:
        return redir
    cur = mysql.connection.cursor()
    cur.execute(
        'SELECT f.FitnessProgramName, f.FP_intensity, f.Description, f.Program_Length, f.MealPlanID, f.WorkoutPlanID '
        'FROM FitnessProgram f WHERE f.FitnessProgramID = %s', (program_id,))
    result = cur.fetchone()
    workout_plan_id = result['WorkoutPlanID']
    meal_plan_id = result['MealPlanID']
    cur.execute('SELECT DISTINCT m.MealName, m.MealType, m.MealDescription '
                'FROM MealPlan_Meal mpm, Meals m WHERE mpm.MealPlanID = %s AND m.MealID IN '
                '(SELECT mpm2.MealID FROM MealPlan_Meal mpm2 WHERE mpm2.MealPlanID = %s)',
                (meal_plan_id, meal_plan_id))
    meal_plan_data = cur.fetchall()
    print(meal_plan_data)
    cur.execute('SELECT w.WorkoutName, w.Equipment, w.Intensity '
                'FROM Workout_Comprise_WPlan wcw, Workouts w WHERE wcw.WorkoutPlanID = %s AND w.WorkoutID IN '
                '(SELECT wcw2.WorkoutID FROM Workout_Comprise_WPlan wcw2 WHERE wcw2.WorkoutPlanID = %s)',
                (workout_plan_id, workout_plan_id))
    workout_plan_data = cur.fetchall()
    print(workout_plan_data)
    cur.close()
    return render_template('client/program_details.html', fitness_program_details=result, meal_plan_data=meal_plan_data,
                           workout_plan_data=workout_plan_data)



@app.route("/client/<int:user_id>/change_program/<program_id>", methods=['POST'])
def client_change_plan(user_id, program_id):
    cur = mysql.connection.cursor()
    redir = ensure_user_is_logged_in_properly(user_id)
    if redir:
        return redir
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
    redir = ensure_user_is_logged_in_properly(user_id)
    if redir:
        return redir
    cur = mysql.connection.cursor()
    cur.execute(
        'SELECT l.LogID, f.FitnessProgramName, l.LogDate, l.Weight, l.WorkoutCompletion, l.Notes, l.SatisfactionLevel, '
        'l.MealCompletion FROM FitnessProgram f, Logs l, Users u WHERE l.UserID = u.UserID AND '
        'l.FitnessProgramID = f.FitnessProgramID AND u.UserID = %s ', [str(user_id)])
    result = cur.fetchall()
    print(result)
    if result:
        log_info = result
    cur.execute("SELECT c.Current_FitnessProgram FROM Clients c WHERE c.UserID = %s", (user_id,))
    current_fitness_program = cur.fetchone()
    print(current_fitness_program)
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
            'l.FitnessProgramID = f.FitnessProgramID AND u.UserID = %s', [str(user_id)])
        result = cur.fetchall()
        if result:
            log_info = result
        cur.close()
        return render_template('client/client_logs.html', log_info=log_info, user_id=user_id,
                               current_fitness_program=current_fitness_program)


# Delete Log

@app.route('/delete_log/<string:logid>', methods=['POST'])
def delete_log(logid):
    # Create Cursor
    cur = mysql.connection.cursor()
    # Store userid
    user_id = cur.execute("select userid FROM Logs where logid=%s", [str(logid)])
    result = cur.fetchone()
    cur.close()
    # Delete Log
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM Logs where logid= %s", [str(logid)])

    mysql.connection.commit()
    cur.close()
    flash('Log Deleted! Go Make Another One!', 'success')
    return redirect(url_for('client_logs', user_id=user_id))


# TRAINER ROUTES


@app.route("/trainer/<int:user_id>/")
def trainer(user_id):
    redir = ensure_user_is_logged_in_properly(user_id)
    if redir:
        return redir
    cur = mysql.connection.cursor()
    cur.execute(
        'SELECT * '
        'FROM Users u WHERE u.UserID = %s AND u.UserID IN (SELECT UserID FROM Trainers)', (user_id,))
    result = cur.fetchone()
    # Division query: Find all clients who are taking all of the trainer's programs (Superstars)
    # If trainer has no fitness program, skip the query (would return all users: divison by zero is infinity)
    num_programs = cur.execute(
        'SELECT * '
        'FROM FitnessProgram '
        'WHERE TrainerID = %s',
        (user_id,)
    )
    programs = None
    superstars = None
    if num_programs > 0:
        programs = cur.fetchall()
        cur.execute(
            'SELECT u.FirstName, u.LastName '
            'FROM Users u '
            'WHERE NOT EXISTS( '
            '  SELECT * '
            '  FROM FitnessProgram f '
            '  WHERE NOT EXISTS( '
            '    SELECT * '
            '    FROM Logs l '
            '    WHERE u.UserID = l.UserID AND '
            '    l.FitnessProgramID = f.FitnessProgramID '
            '  ) AND '
            '  f.TrainerID = %s '
            ')', (user_id,)
        )
        superstars = cur.fetchall()
    clients = None
    num_clients = cur.execute(
        'SELECT DISTINCT u.FirstName, u.LastName '
        'FROM Users u, Logs l, FitnessProgram f '
        'WHERE u.UserID = l.UserID AND '
        'l.FitnessProgramID = f.FitnessProgramID AND '
        'f.TrainerID = %s', (user_id,)
    )
    if num_clients > 0:
        clients = cur.fetchall()
    logs = None
    num_logs = cur.execute(
        'SELECT l.LogID, l.SatisfactionLevel '
        'FROM Logs l, FitnessProgram f '
        'WHERE l.FitnessProgramID = f.FitnessProgramID AND '
        'f.TrainerID = %s', (user_id,)
    )
    if num_logs > 0:
        logs = cur.fetchall()
    cur.close()
    if result:
        return render_template('trainer/dashboard.html',
                               user=result, user_id=user_id, superstars=superstars,
                               programs=programs, clients=clients, logs=logs)
    else:
        return redirect('/')


@app.route("/trainer/<int:user_id>/all_programs/")
def trainer_all_plans(user_id, plan_info=None):
    # All fitness plans made by all of the trainers
    redir = ensure_user_is_logged_in_properly(user_id)
    if redir:
        return redir
    cur = mysql.connection.cursor()
    cur.execute('SELECT COUNT(*) FROM FitnessProgram f, Users u WHERE f.TrainerID = u.UserID')
    count = cur.fetchone()['COUNT(*)']
    cur.execute(
        'SELECT f.FitnessProgramID, u.FirstName, u.LastName, f.FP_intensity, f.Description, f.Program_Length, '
        'f.MealPlanID, f.WorkoutPlanID '
        'FROM FitnessProgram f, Users u WHERE f.TrainerID = u.UserID')
    result = cur.fetchall()

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
        redir = ensure_user_is_logged_in_properly(user_id)
        if redir:
            return redir
        cur = mysql.connection.cursor()
        cur.execute(
            'SELECT f.FitnessProgramID, u.FirstName, u.LastName, u.UserName, f.FP_intensity, f.Description, f.Program_Length, '
            'f.MealPlanID, f.WorkoutPlanID '
            'FROM FitnessProgram f, Users u WHERE f.TrainerID = u.UserID AND u.UserID = %s', [str(user_id)])
        result = cur.fetchall()
        cur.execute(
            'SELECT * '
            'FROM MealPlan m')
        meal_plans = cur.fetchall()
        cur.execute(
            'SELECT * '
            'FROM WorkoutPlan w')
        workout_plans = cur.fetchall()

        plan_info = result
        cur.close()
        return render_template('trainer/trainer_plans.html', plan_info=plan_info, user_id=user_id,
                               meal_plans=meal_plans,
                               workout_plans=workout_plans)


@app.route("/trainer/<int:user_id>/programs/<int:program_id>")
def trainer_plan_detail(user_id, program_id):
    cur = mysql.connection.cursor()
    cur.execute(
        'SELECT f.FitnessProgramName, f.Description, f.Program_Length '
        'FROM FitnessProgram f WHERE f.FitnessProgramID = %s ', (program_id,))
    program_details = cur.fetchone()
    cur.execute(
        'SELECT COUNT(c.UserID) '
        'FROM FitnessProgram f, Clients c WHERE f.FitnessProgramID = %s '
        'AND f.FitnessProgramID = c.Current_FitnessProgram', (program_id,))
    client_count = cur.fetchone()
    cur.execute(
        'SELECT c.UserID, u.UserName, COUNT(l.LogID), u.Gender, u.Age '
        'FROM FitnessProgram f, Clients c, Logs l, Users u '
        'WHERE f.FitnessProgramID = %s AND f.FitnessProgramID = c.Current_FitnessProgram AND '
        'c.UserID = u.UserID AND l.UserID = c.UserID AND l.FitnessProgramID = f.FitnessProgramID '
        'GROUP BY c.UserID '
        'ORDER BY COUNT(l.LogID) DESC',
        (program_id,))
    client_details = cur.fetchall()
    print(client_details)
    cur.close()
    return render_template('trainer/plan_details.html', user_id=user_id, program_details=program_details,
                           client_details=client_details, client_count=client_count)


@app.route("/trainer/<int:user_id>/meal_plans/")
def trainer_meal_plans(user_id):
    # Only the meal plans made by the trainer
    redir = ensure_user_is_logged_in_properly(user_id)
    if redir:
        return redir
    cur = mysql.connection.cursor()
    cur.execute(
        'SELECT m.MealPlanID, m.Category, m.DietaryRestrictions, m.MealPlanDescription, '
        'f.FitnessProgramID FROM FitnessProgram f, MealPlan m, Users u WHERE f.TrainerID = u.UserID AND '
        'm.MealPlanID = f.MealPlanID AND u.UserID = %s', [str(user_id)])
    result = cur.fetchall()
    print(result)

    plan_info = result
    cur.close()
    return render_template('trainer/meal_plans.html', meal_plan_info=plan_info, user_id=user_id)

#Creating a new meal plan

class MealPlanForm(Form):
    mealplanname = StringField('mealplanname', [
        validators.DataRequired(),
        validators.Length(min=1, max=50)])
    category = StringField('category', [
        validators.DataRequired(),
        validators.Length(min=1, max=50)])
    dietaryrestrictions = StringField('dietaryrestrictions', [
        validators.DataRequired(),
        validators.Length(min=1, max=50)])
    mealplandescription = StringField('mealplandescription', [
        validators.DataRequired(),
        validators.Length(min=1, max=400)])


@app.route("/trainer/<int:user_id>/create_mealplan/", methods=['GET','POST'])
def create_mealplan(user_id):
    form = MealPlanForm(request.form)
    if request.method == 'POST' and form.validate():
        #Form Fields
        mealplanname = form.mealplanname.data
        category = form.category.data
        dietaryrestrictions = form.dietaryrestrictions.data
        mealplandescription = form.mealplandescription.data
        #Checking to see if a mealplan has that name
        cur = mysql.connection.cursor()
        mealplan_check = cur.execute(
            'SELECT * from MealPlan where MealPlanName = %s', [mealplanname]
        )
        cur.close()
        if mealplan_check > 0:
            flash('The Meal Plan Name is already taken! Try another one', 'danger')
            return render_template('trainer/create_mealplan.html', user_id=user_id,form=form)
        #Creating MealPlan
        cur = mysql.connection.cursor()
        cur.execute(
            'INSERT INTO MealPlan(MealPlanName, Category, DietaryRestrictions, MealPlanDescription) '
            'VALUES(%s,%s,%s,%s)', (mealplanname, category,dietaryrestrictions,mealplandescription)
        )
        mysql.connection.commit()
        cur.close()
        #Fetching MealPlanID
        cur = mysql.connection.cursor()
        cur.execute(
            'SELECT * from MealPlan where MealPlanName = %s', [mealplanname]
        )
        result = cur.fetchone()
        mealplanid = result['MealPlanID']
        cur.close()
        flash('Meal plan created! Go add some meals in!', 'success')
        return redirect(url_for('create_mealplan2', user_id=user_id, mealplanid = mealplanid))

    return render_template('trainer/create_mealplan.html', user_id=user_id,form=form)
    #ROUTE WORKS
@app.route("/trainer/<int:user_id>/<int:mealplanid>/create_mealplan2/", methods=['GET','POST'])
def create_mealplan2(user_id, mealplanid):
    if request.method == 'POST':
        # Get Form Fields
        MealName = request.form['MealName']
        MealNamePassed = '%' + MealName + '%'
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM Meals WHERE MealName LIKE %s ", [MealNamePassed])
        meals = cur.fetchall()

        if result > 0:
            flash('Matches Found', 'success')
            cur.close()
            return render_template('trainer/create_mealplan2.html', user_id=user_id, mealplanid = mealplanid, meals=meals)
        else:
            cur.close()
            return redirect(url_for('create_mealplan2', user_id=user_id, mealplanid = mealplanid))


    else:
        #Display Meals
        cur = mysql.connection.cursor()
        result = cur.execute("select * from Meals")
        meals = cur.fetchall()

        if result > 0:
            cur.close()
            return render_template('trainer/create_mealplan2.html', user_id=user_id, mealplanid = mealplanid, meals=meals)
            #return render_template('meals.html', meals=Meals)
        else:
            flash('No Meals Found Try Again!', 'danger')
            cur.close()
            return redirect(url_for('create_mealplan2', user_id=user_id, mealplanid = mealplanid))
            #return render_template('meals.html', msg=msg)



@app.route('/add_meal_to_mealplan/<user_id>/<string:mealplanid>/<string:mealid>', methods=['POST'])
def add_meal_2_mealplan(user_id,mealplanid,mealid):
    #check if meal in mealplan
    cur = mysql.connection.cursor()
    result = cur.execute(
        'select * from MealPlan_Meal where MealPlanID = %s AND MealID = %s', (mealplanid, mealid)
    )
    if result > 0:
        flash("You already added this meal", 'danger')
        cur.close()
        return redirect(url_for('create_mealplan2', user_id=user_id, mealplanid = mealplanid))
    cur.close()
    #Let's add meal to mealplan
    cur = mysql.connection.cursor()
    cur.execute(
        'select * from MealPlan where MealPlanID = %s', [mealplanid]
    )
    result = cur.fetchone()
    mealplanname = result['MealPlanName']
    cur.close()
    cur = mysql.connection.cursor()
    cur.execute(
        'INSERT INTO MealPlan_Meal(MealPlanID,MealPlanName,MealID) VALUES(%s,%s,%s)',(mealplanid, mealplanname,mealid)
    )
    mysql.connection.commit()
    cur.close()
    flash('Meal added to your MealPlan', 'success')
    return redirect(url_for('create_mealplan2', user_id=user_id, mealplanid = mealplanid))


@app.route("/trainer/<int:user_id>/workout_plans/")
def trainer_workout_plans(user_id):
    # Only the meal plans made by the trainer
    redir = ensure_user_is_logged_in_properly(user_id)
    if redir:
        return redir
    cur = mysql.connection.cursor()
    cur.execute(
        'SELECT w.WorkoutPlanID, w.Intensity, w.PlanDescription, '
        'f.FitnessProgramID FROM FitnessProgram f, WorkoutPlan w, Users u WHERE f.TrainerID = u.UserID AND '
        'w.WorkoutPlanID = f.WorkoutPlanID AND u.UserID = %s', [str(user_id)])
    result = cur.fetchall()

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


class WorkOutPlanForm(Form):
    workoutplanname = StringField('workoutplanname', [
        validators.DataRequired(),
        validators.Length(min=1, max=100)])
    intensity = StringField('intensity', [
        validators.DataRequired(),
        validators.Length(min=1, max=50)])
    plandescription = StringField('plandescription', [
        validators.DataRequired(),
        validators.Length(min=1, max=400)])  

@app.route("/trainer/<int:user_id>/create_workoutplan/", methods=['GET','POST'])
def create_workoutplan(user_id):
    form = WorkOutPlanForm(request.form)
    if request.method == 'POST' and form.validate():
        #FORM FIELDS
        workoutplanname = form.workoutplanname.data
        intensity = form.intensity.data
        plandescription = form.plandescription.data
        #Check to see if workoutplan already exists 
        cur = mysql.connection.cursor()
        workoutplan_check = cur.execute(
            'select * from WorkoutPlan where WorkoutPlanName = %s ', [workoutplanname]
        )
        if workoutplan_check > 0:
            cur.close()
            flash('The Work Out Plan Name is already taken! Try another one!', 'danger')
            return render_template('trainer/workout_plans.html', user_id=user_id, form=form)
        cur.close()
        #SUCCESS name not taken, create plan
        cur = mysql.connection.cursor()
        cur.execute(
            'INSERT into WorkoutPlan(WorkoutPlanName, Intensity, PlanDescription) '
            'VALUES(%s,%s,%s)', (workoutplanname, intensity, plandescription)
        )
        mysql.connection.commit()
        cur.close()
        cur = mysql.connection.cursor()
        cur.execute(
            'SELECT * from WorkoutPlan where WorkoutPlanName = %s', [workoutplanname]
        )
        result = cur.fetchone()
        workoutplanid = result['WorkoutPlanID']
        cur.close()
        flash('Work Out Plan Created!', 'success')
        return redirect(url_for('create_workout_plan2', user_id=user_id, workoutplanid = workoutplanid))
    return render_template('trainer/create_workout_plan.html', user_id=user_id,form=form)


@app.route("/trainer/<int:user_id>/<int:workoutplanid>/create_workoutplan2/", methods=['GET','POST'])
def create_workout_plan2(user_id, workoutplanid):
    if request.method == 'POST':
        #Get workoutname
        workoutname = request.form['WorkoutName']
        workoutnamepassed = '%' + workoutname + '%'
        cur = mysql.connection.cursor()
        result = cur.execute(
            'select * from Workouts where WorkoutName like %s', [workoutnamepassed]
        )
        workouts = cur.fetchall()

        if result > 0:
            flash('Matches Found', 'success')
            cur.close()
            return render_template('trainer/create_workout_plan2.html', user_id=user_id, workoutplanid = workoutplanid, workouts=workouts)
        else:
            flash("No Matches Found", 'danger')
            cur.close()
            return redirect(url_for('create_workout_plan2', user_id=user_id, workoutplanid = workoutplanid))
    else:
        #Display Workouts
        cur = mysql.connection.cursor()
        result = cur.execute("select * from Workouts")
        workouts = cur.fetchall()

        if result > 0:
            cur.close()
            return render_template('trainer/create_workout_plan2.html', user_id=user_id, workoutplanid = workoutplanid, workouts=workouts)
            #return render_template('meals.html', meals=Meals)
        else:
            flash('No Workouts Found Try Again!', 'danger')
            cur.close()
            return redirect(url_for('create_workout_plan2', user_id=user_id, workoutplanid = workoutplanid))
            #return render_template('meals.html', msg=msg)


  
@app.route('/add_workout_to_workoutplan/<user_id>/<string:workoutplanid>/<string:workoutid>', methods=['POST'])
def add_workout_2_workoutplan(user_id,workoutplanid,workoutid):
    #Check if workout is in workoutplan
    cur = mysql.connection.cursor()
    result = cur.execute(
        'select * from Workout_Comprise_WPlan where WorkoutPlanID = %s and WorkOutID = %s', [workoutplanid, workoutid]
    )
    if result > 0:
        flash("You've already added this workout!", 'danger')
        cur.close()
        return redirect(url_for('create_workout_plan2', user_id=user_id, workoutplanid = workoutplanid))
    cur.close()
    #Workout does not exist in Workoutplan, lets add. First find workoutplan name
    cur = mysql.connection.cursor()
    cur.execute(
        'select * from WorkoutPlan where WorkoutPlanID = %s', [workoutplanid]
    )
    result = cur.fetchone()
    workoutplanname = result['WorkoutPlanName']
    cur.close()
    cur = mysql.connection.cursor()
    cur.execute(
        'INSERT into Workout_Comprise_WPlan(WorkoutPlanID, WorkoutPlanName, WorkoutID) '
        'VALUES(%s,%s,%s)', (workoutplanid, workoutplanname, workoutid)
    )
    mysql.connection.commit()
    cur.close()
    flash("Workout has been added to your workoutplan!", 'success')
    return redirect(url_for('create_workout_plan2', user_id=user_id, workoutplanid = workoutplanid))


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
    result = cur.execute("SELECT * FROM Workouts WHERE WorkoutID = %s", (workoutID,))
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
