import json
from os import environ as env
from urllib.parse import quote_plus, urlencode
from datetime import datetime

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for, request
from functools import wraps
import logging

# Load environment variables
ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

# Logging setup
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

# Auth0 configuration
oauth = OAuth(app)
oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={"scope": "openid profile email"},
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

# Routes
@app.route("/")
def home():
    return render_template(
        "home.html",
        session=session.get("user"),
        pretty=json.dumps(session.get("user"), indent=4),
    )

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback")
def callback():
    token = oauth.auth0.authorize_access_token()
    userinfo = token.get("userinfo")
    if not userinfo:
        # fallback: manually get userinfo using token
        userinfo_endpoint = oauth.auth0.load_server_metadata().get("userinfo_endpoint")
        resp = oauth.auth0.get(userinfo_endpoint)
        userinfo = resp.json()

    session["user"] = userinfo
    app.logger.info({
        "event": "login",
        "user_id": userinfo.get("sub"),
        "email": userinfo.get("email"),
        "timestamp": datetime.utcnow().isoformat()
    })
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        f'https://{env.get("AUTH0_DOMAIN")}/v2/logout?' +
        urlencode({
            "returnTo": url_for("home", _external=True),
            "client_id": env.get("AUTH0_CLIENT_ID"),
        }, quote_via=quote_plus)
    )

# Authorization decorator
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            # Log unauthorized access
            app.logger.warning(json.dumps({
                "event": "unauthorized_access",
                "ip": request.remote_addr,
                "path": request.path,
                "timestamp": datetime.utcnow().isoformat()
            }))
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated

@app.route("/protected")
@requires_auth
def protected():
    user = session.get("user")

    # Log access to /protected
    app.logger.info(json.dumps({
        "event": "access_protected",
        "user_id": user.get("sub"),
        "username": user.get("nickname") or user.get("name"),
        "email": user.get("email"),
        "timestamp": datetime.utcnow().isoformat()
    }))

    return render_template(
        "protected.html",
        session=user,
        pretty=json.dumps(user, indent=4),
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(env.get("PORT", 3000)))
