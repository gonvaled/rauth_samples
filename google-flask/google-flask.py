"""
    google
    ------

    A simple Flask demo app that shows how to login with Google via rauth.

    Due to Google's stringent domain validation, requests using this app
    must originate from 127.0.0.1:5000.

    You must configure the redirect_uri in the Google API console. In this case,
    it is: http://127.0.0.1:5000/google/authorized
"""

from flask import Flask, flash, request, redirect, render_template, url_for
from flask.ext.sqlalchemy import SQLAlchemy

from rauth.service import OAuth2Service

import time

# Flask config
SQLALCHEMY_DATABASE_URI = 'sqlite:///google.db'
SECRET_KEY = '^\x04\x12\tw.;\x9a\xe1Ws\x99\x1eh\xb9\xa8\xb5\xc4\x05-\xe0d\xedq'
DEBUG = True

from secrets import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI, GOOGLE_TEST_EMAIL

# Flask setup
app = Flask(__name__)
app.config.from_object(__name__)
db = SQLAlchemy(app)

# rauth OAuth 2.0 service wrapper
google = OAuth2Service(name='google',
                       authorize_url='https://accounts.google.com/o/oauth2/auth',
                       access_token_url='https://accounts.google.com/o/oauth2/token',
                       client_id=app.config['GOOGLE_CLIENT_ID'],
                       client_secret=app.config['GOOGLE_CLIENT_SECRET'],
                       base_url=None)

# models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    google_id = db.Column(db.String(120))
    access_token = db.Column(db.String(500))
    expires_at = db.Column(db.Integer)
    refresh_token = db.Column(db.String(500))

    def __init__(self, username, google_id, access_token, expires_at, refresh_token):
        self.username = username
        self.google_id = google_id
        self.access_token = access_token
        self.expires_at = expires_at
        self.refresh_token = refresh_token

    def __repr__(self):
        return '<User %r>' % self.username

    @staticmethod
    def get(username):
        user = User.query.filter_by(username=username).first()
        return user

    @staticmethod
    def delete(username):
        user = User.query.filter_by(username=username).first()
        db.session.delete(user)
        db.session.commit()

    @staticmethod
    def get_or_create(username, google_id, access_token, expires_at, refresh_token):
        user = User.query.filter_by(username=username).first()
        if user is None:
            user = User(username, google_id, access_token, expires_at, refresh_token)
            db.session.add(user)
            db.session.commit()
        return user

def display_user(access_token, txt, response=None):
    ''' If response is given, we assume the user must be created, with the parameters present in the response'''
    # setup the session using the access_token
    oauth_session = google.get_session(access_token)

    # the user object as returned by google
    user = oauth_session.get('https://www.googleapis.com/oauth2/v1/userinfo').json()

    # create the user, save the access_token, and the expire_at, so that
    # we can later verify if the access token is still valid
    if response :
        expires_in = response['expires_in']
        expires_at = int(time.time()) + response['expires_in']
        try:
            refresh_token = response['refresh_token']
        except:
            refresh_token = None
        User.get_or_create(user['email'], user['id'], access_token, expires_at, refresh_token)

    flash(txt + user['email'])
    return redirect(url_for('index'))

# views
@app.route('/')
def index():
    return render_template('login.html')

@app.route('/google/login')
def login():
    redirect_uri = url_for('authorized', _external=True)
    params = {
        'scope': 'email',
        'response_type': 'code',
        'redirect_uri': redirect_uri,
        'access_type' : 'offline',
    }
    return redirect(google.get_authorize_url(**params))

@app.route('/google/force')
def force():
    redirect_uri = url_for('authorized', _external=True)
    params = {
        'scope': 'email',
        'response_type': 'code',
        'redirect_uri': redirect_uri,
        'access_type' : 'offline',
        'approval_prompt' : 'force',
    }
    return redirect(google.get_authorize_url(**params))

@app.route('/google/refresh')
def refresh():
    user = User.get(GOOGLE_TEST_EMAIL)
    response = google.get_raw_access_token(data={
        'refresh_token': user.refresh_token,
        'grant_type': 'refresh_token',
    })
    response = response.json()
    return display_user(response['access_token'], 'Refreshed logging session as ')

@app.route('/google/reuse')
def reuse():
    user = User.get(GOOGLE_TEST_EMAIL)
    if not user:
        flash('User ' + GOOGLE_TEST_EMAIL + ' is not known yet')
        return redirect(url_for('login'))
    current = int(time.time())
    remaining = user.expires_at - current
    print "remaining=%d" % (remaining)
    if remaining <= 0:
        flash('Authorization token for user ' + user['email'] + ' has expired')
        return redirect(url_for('refresh'))
    return display_user(user.access_token, 'Reused logging session as ')

@app.route('/google/authorized')
def authorized():
    # check to make sure the user authorized the request
    if not 'code' in request.args:
        flash('You did not authorize the request')
        return redirect(url_for('index'))
    code = request.args['code']

    # make a request for the access token credentials using code
    redirect_uri = url_for('authorized', _external=True)
    data = {
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': redirect_uri,
    }
    response = google.get_raw_access_token(data=data)
    response = response.json()

    return display_user(response['access_token'], 'Authorized as ', response)

@app.route('/google/forget')
def forget():
    User.delete(GOOGLE_TEST_EMAIL)
    flash('Forgot user ' + GOOGLE_TEST_EMAIL)
    return redirect(url_for('index'))

if __name__ == '__main__':
    db.create_all()
    app.run()
