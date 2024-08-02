from flask import *
from flask_sqlalchemy import SQLAlchemy
import re
# import traceback
import bcrypt

# initialize flask
app = Flask(__name__)
app.secret_key = 'hi'

# Set SQLAlchemy config
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/flask_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)


@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ''
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Check if the email or password fields are empty
        if not email or not password:
            message = 'Please enter your email and password!'
        else:
            user = User.query.filter_by(email=email).first()
            
            if user:
                try:
                    # Check password with bcrypt
                    if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
                        session['loggedin'] = True
                        session['id'] = user.id
                        session['name'] = user.name
                        session['email'] = user.email
                        message = 'Logged in successfully!'
                        return render_template('user.html', message=message)
                    else:
                        message = 'Please enter correct email/password!'
                except:
                    message = 'An error occurred while checking the password.'
            else:
                message = 'User does not exist! Please register.'
    
    return render_template('login.html', message=message)


# Make function for logout session
@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('userid', None)
    session.pop('email', None)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    message = ''
    if request.method == 'POST':
        userName = request.form.get('name')
        password = request.form.get('password')
        email = request.form.get('email')
        
        # Check if any field is empty
        if not userName or not password or not email:
            message = 'Please fill out the form!'
        else:
            account = User.query.filter_by(email=email).first()
            if account:
                message = 'Account already exists!'
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                message = 'Invalid email address!'
            else:
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                new_user = User(name=userName, email=email, password=hashed_password.decode('utf-8'))
                db.session.add(new_user)
                db.session.commit()
                message = 'You have successfully registered!'
    
    return render_template('register.html', message=message)

# run code in debug mode
if __name__ == "__main__":
    app.run(debug=True)