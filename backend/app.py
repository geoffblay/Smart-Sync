from flask import Flask, redirect, request, url_for, session, render_template_string
from dotenv import load_dotenv
import os
import requests
import firebase_admin
from firebase_admin import credentials, firestore
import logging
from flask_session import Session
import secrets

load_dotenv()

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(16)
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

os.environ["FIRESTORE_EMULATOR_HOST"] = os.getenv(
    "FIRESTORE_EMULATOR_HOST", "localhost:8080"
)

cred = credentials.Certificate(r"firebase-credentials.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

logging.basicConfig(level=logging.INFO)  # Adjust to DEBUG for more details
app.logger.setLevel(logging.INFO)


def log_database():
    docs = db.collection("users").stream()
    app.logger.info("Entries in the database:")
    for doc in docs:
        app.logger.info(f"{doc.id}: {doc.to_dict()}")


# Replace with your Strava app's credentials
STRAVA_CLIENT_ID = os.getenv("STRAVA_CLIENT_ID")
STRAVA_CLIENT_SECRET = os.getenv("STRAVA_CLIENT_SECRET")
REDIRECT_URI = "http://localhost:5001/auth/callback"  # Your redirect URI


@app.route("/")
def connect_strava():
    strava_auth_url = (
        f"https://www.strava.com/oauth/authorize"
        f"?client_id={STRAVA_CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=activity:read_all,activity:write"
    )
    app.logger.info(strava_auth_url)
    return redirect(strava_auth_url)


@app.route("/auth/callback")
def auth_callback():
    # Get the authorization code from the query parameters
    auth_code = request.args.get("code")
    if not auth_code:
        return "Authorization failed. No code provided.", 400

    # Exchange the authorization code for an access token
    token_response = requests.post(
        "https://www.strava.com/oauth/token",
        data={
            "client_id": STRAVA_CLIENT_ID,
            "client_secret": STRAVA_CLIENT_SECRET,
            "code": auth_code,
            "grant_type": "authorization_code",
        },
    )

    # Parse the response
    token_data = token_response.json()
    if "access_token" in token_data:
        # Save tokens and user information to the database
        user_id = token_data["athlete"]["id"]
        access_token = token_data["access_token"]
        refresh_token = token_data["refresh_token"]
        expires_at = token_data["expires_at"]
        save_user_tokens(str(user_id), access_token, refresh_token, expires_at)
        # redirect to preferences page
        return redirect(url_for("preferences"))
    else:
        return f"Error: {token_data.get('message', 'Failed to retrieve token')}"


def save_user_tokens(user_id, access_token, refresh_token, expires_at):
    # Example logic to save tokens to a database
    # Replace this with actual database code
    app.logger.info(f"Saving user {user_id} with access token {access_token}")
    users_ref = db.collection("users")
    users_ref.document(user_id).set(
        {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_at": expires_at,
        }
    )
    session["user_id"] = user_id
    session["access_token"] = access_token


# preferences page
@app.route("/preferences", methods=["GET", "POST"])
def preferences():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for('/'))  # or another appropriate route

    if request.method == "POST":
        # Get selected activities from the form
        selected_activities = request.form.getlist("activity")
        # Update user preferences in Firestore
        users_ref = db.collection("users")
        users_ref.document(user_id).update({"activities": selected_activities})
        return "Preferences updated successfully!"

    # Retrieve current preferences from Firestore
    users_ref = db.collection("users")
    user_doc = users_ref.document(user_id).get()
    current_preferences = user_doc.to_dict().get("activities", [])

    # Display the form with checkboxes, pre-selecting the current preferences
    activities = ["run", "swim", "bike", "lift", "walk"]
    form_html = """
    <form action="/preferences" method="post">
        {% for activity in activities %}
            <input type="checkbox" name="activity" value="{{ activity }}" {% if activity in current_preferences %}checked{% endif %}> {{ activity.capitalize() }}<br>
        {% endfor %}
        <input type="submit" value="Submit">
    </form>
    """
    return render_template_string(form_html, activities=activities, current_preferences=current_preferences)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
