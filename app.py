from flask import Flask, render_template, url_for, request, abort, redirect

app = Flask(__name__)

# Route for landing page
@app.route("/")
def base():
    return render_template('base.html')

# Route for sign up form
@app.route("/signup")
def signup():
    return render_template('auth/signup.html')

# Route for sign up form
@app.route("/login")
def login():
    return render_template('auth/login.html')

# Note: This is in debug mode. This means that it restarts with changes
if __name__ == "__main__":
    app.run(debug=True)
    
