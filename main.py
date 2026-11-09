import os
from flask import Flask, redirect, url_for, session, render_template
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "").strip()
if not app.secret_key:
    raise RuntimeError("SECRET_KEY must be set to a strong, private value.")

ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "the27linksofficial@gmail.com").strip().casefold()
if not ADMIN_EMAIL:
    raise RuntimeError("ADMIN_EMAIL must be set to the Google account allowed to access the dashboard.")

# Set DATABASE_URL to the Neon connection string provided by your project.
DATABASE_URL = os.environ.get('DATABASE_URL', '').strip()
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL must be set to your Neon PostgreSQL connection string.")

if DATABASE_URL.startswith('postgresql://'):
    DATABASE_URL = DATABASE_URL.replace('postgresql://', 'postgresql+psycopg://', 1)
elif DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql+psycopg://', 1)
elif DATABASE_URL.startswith('postgresql+psycopg2://'):
    DATABASE_URL = DATABASE_URL.replace('postgresql+psycopg2://', 'postgresql+psycopg://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_pre_ping': True}
db = SQLAlchemy(app)

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(120))
    picture = db.Column(db.String(255))

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/ping')
def ping():
    return {"status": "awake"}, 200

@app.route('/health')
def health():
    try:
        with db.engine.connect() as connection:
            connection.execute(text('SELECT 1'))
    except SQLAlchemyError:
        app.logger.exception("Neon database health check failed")
        return {"status": "database unavailable"}, 503
    return {"status": "ok"}, 200

@app.route('/login')
def login():
    redirect_uri = url_for('auth', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/callback')
def auth():
    token = google.authorize_access_token()
    user_info = token.get('userinfo')
    if not isinstance(user_info, dict) or not user_info.get('email'):
        app.logger.error("Google OAuth callback did not include a user email.")
        return {"error": "Google did not return an account email."}, 400

    try:
        user = User.query.filter_by(email=user_info['email']).first()
        if not user:
            user = User(
                email=user_info['email'],
                name=user_info.get('name'),
                picture=user_info.get('picture'),
            )
            db.session.add(user)
            db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Failed to load or save the authenticated user.")
        raise

    session['user'] = user_info
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    user = session.get('user')
    if not user or (user.get('email') or '').strip().casefold() != ADMIN_EMAIL:
        return "Access Denied: Unauthorized Account", 403
        
    all_users = User.query.all()
    return render_template('dashboard.html', users=all_users, admin=user)
