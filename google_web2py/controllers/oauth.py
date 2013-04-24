import time
from rauth.service import OAuth2Service

from secrets import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI, GOOGLE_TEST_EMAIL

# rauth OAuth 2.0 service wrapper
google = OAuth2Service(name='google',
                       authorize_url='https://accounts.google.com/o/oauth2/auth',
                       access_token_url='https://accounts.google.com/o/oauth2/token',
                       client_id=GOOGLE_CLIENT_ID,
                       client_secret=GOOGLE_CLIENT_SECRET,
                       base_url=None)

def display_user(access_token, txt, google_response=None):
    ''' If google_response is given, we assume the user must be created, with the parameters present in the google_response'''
    # setup the session using the access_token
    oauth_session = google.get_session(access_token)

    # the user object as returned by google
    user = oauth_session.get('https://www.googleapis.com/oauth2/v1/userinfo').json()

    # create the user, save the access_token, and the expire_at, so that
    # we can later verify if the access token is still valid
    if google_response :
        expires_in = google_response['expires_in']
        expires_at = int(time.time()) + expires_in
        try:
            refresh_token = google_response['refresh_token']
        except:
            refresh_token = None
        db.google.insert(username=user['email'], google_id=user['id'], access_token=access_token, expires_at=expires_at, refresh_token=refresh_token)

    session.flash = txt + user['email']
    redirect(URL('index'))

def index():
    return dict(message=T('Hello World'))

def login():
    redirect_uri = URL('authorized', scheme=True, host=True)
    params = {
        'scope': 'email',
        'response_type': 'code',
        'redirect_uri': redirect_uri,
        'access_type' : 'offline',
    }
    redirect(google.get_authorize_url(**params))

def force():
    redirect_uri = URL('authorized', scheme=True, host=True)
    params = {
        'scope': 'email',
        'response_type': 'code',
        'redirect_uri': redirect_uri,
        'access_type' : 'offline',
        'approval_prompt' : 'force',
    }
    redirect(google.get_authorize_url(**params))

def refresh():
    user = db(db.google.username==GOOGLE_TEST_EMAIL).select().first()
    google_response = google.get_raw_access_token(data={
        'refresh_token': user.refresh_token,
        'grant_type': 'refresh_token',
    })
    google_response = google_response.json()
    return display_user(google_response['access_token'], 'Refreshed logging session as ')

def reuse():
    user = db(db.google.username==GOOGLE_TEST_EMAIL).select().first()
    if not user:
        session.flash = 'User ' + GOOGLE_TEST_EMAIL + ' is not known yet'
        redirect(URL('login'))
    current = int(time.time())
    remaining = user.expires_at - current
    if remaining <= 0:
        session.flash = 'Authorization token for user ' + user['email'] + ' has expired'
        redirect(URL('refresh'))
    return display_user(user.access_token, 'Remaining ' + str(remaining) + ' s. Reused logging session as ')

def authorized():
    # check to make sure the user authorized the request
    if not 'code' in request.vars:
        session.flash = 'You did not authorize the request'
        redirect(URL('index'))
    code = request.vars['code']

    # make a request for the access token credentials using code
    redirect_uri = URL('authorized', scheme=True, host=True)
    data = {
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': redirect_uri,
    }
    google_response = google.get_raw_access_token(data=data)
    google_response = google_response.json()

    return display_user(google_response['access_token'], 'Authorized as ', google_response)

def forget():
    db(db.google.username == GOOGLE_TEST_EMAIL).delete()
    session.flash = 'Forgot user ' + GOOGLE_TEST_EMAIL
    redirect(URL('index'))
