from flask import (
    Flask,
    redirect,
    request,
    url_for,
    session,
    render_template_string,
    jsonify,
    make_response,
)
from dotenv import load_dotenv
import os
import requests
import firebase_admin
from firebase_admin import credentials, firestore
import logging
from flask_session import Session
import secrets
import time
from functools import wraps

load_dotenv()

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(16)
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

os.environ["FIRESTORE_EMULATOR_HOST"] = os.getenv(
    "FIRESTORE_EMULATOR_HOST", "localhost:8080"
)

cred = credentials.Certificate(r"../firebase-credentials.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

logging.basicConfig(level=logging.INFO)  # Adjust to DEBUG for more details
app.logger.setLevel(logging.INFO)

STRAVA_CLIENT_ID = os.getenv("STRAVA_CLIENT_ID")
STRAVA_CLIENT_SECRET = os.getenv("STRAVA_CLIENT_SECRET")
AUTH_REDIRECT_URI = "http://localhost:5001/auth/callback"  # Your redirect URI for auth
WEBHOOK_CALLBACK_URI = "https://organic-certain-joey.ngrok-free.app/webhook"  # Your redirect URI for webhook

# ------------------ Helper functions ------------------

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id") or request.cookies.get("user_id")

        if not user_id or not get_valid_access_token(user_id):
            return redirect(url_for("connect_strava"))  # Redirect to Strava auth

        return f(*args, **kwargs)

    return decorated_function


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

    response = make_response(redirect(url_for("preferences")))
    response.set_cookie(
        "user_id",
        user_id,
        max_age=30 * 24 * 60 * 60,
        httponly=True,
        secure=True,
        samesite="None",
    )
    return response


def get_valid_access_token(user_id):
    users_ref = db.collection("users")
    user_doc = users_ref.document(user_id).get()

    if not user_doc.exists:
        return None  # User not found

    user_data = user_doc.to_dict()
    access_token = user_data.get("access_token")
    refresh_token = user_data.get("refresh_token")
    expires_at = user_data.get("expires_at", 0)

    # If the access token is expired, refresh it
    if time.time() >= expires_at:
        app.logger.info(f"Refreshing expired access token for user {user_id}...")

        response = requests.post(
            "https://www.strava.com/oauth/token",
            data={
                "client_id": STRAVA_CLIENT_ID,
                "client_secret": STRAVA_CLIENT_SECRET,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
        )

        new_token_data = response.json()
        if "access_token" in new_token_data:
            new_access_token = new_token_data["access_token"]
            new_refresh_token = new_token_data["refresh_token"]
            new_expires_at = new_token_data["expires_at"]

            # Update Firestore with new tokens
            users_ref.document(user_id).update(
                {
                    "access_token": new_access_token,
                    "refresh_token": new_refresh_token,
                    "expires_at": new_expires_at,
                }
            )

            return new_access_token
        else:
            return None  # Token refresh failed
    else:
        return access_token
    
# def log_database():
#     docs = db.collection("users").stream()
#     app.logger.info("Entries in the database:")
#     for doc in docs:
#         app.logger.info(f"{doc.id}: {doc.to_dict()}")

# ------------------ Routes ------------------

@app.route("/")
def home():
    return """
        <h1>Welcome to SmartSync!</h1>
        <p>Click the button below to connect to Strava and set your preferences.</p>
        <a href="/connect"><button>Connect to Strava</button></a>
    """


@app.route("/connect")
def connect_strava():
    user_id = session.get("user_id") or request.cookies.get("user_id")
    if user_id:
        return redirect(url_for("preferences"))

    strava_auth_url = (
        f"https://www.strava.com/oauth/authorize"
        f"?client_id={STRAVA_CLIENT_ID}"
        f"&redirect_uri={AUTH_REDIRECT_URI}"
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


@app.route("/preferences", methods=["GET", "POST"])
@login_required
def preferences():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("/"))

    if request.method == "POST":
        # Get selected activities from the form
        selected_activities = request.form.getlist("activity")
        
        # Update user preferences in Firestore
        users_ref = db.collection("users")
        users_ref.document(user_id).update({"activities": selected_activities})

        # Create a webhook subscription for the user
        access_token = session.get("access_token")
        headers = {"Authorization": f"Bearer {access_token}"}
        data = {
            "client_id": STRAVA_CLIENT_ID,
            "client_secret": STRAVA_CLIENT_SECRET,
            "callback_url": WEBHOOK_CALLBACK_URI,
            "verify_token": "STRAVA",
        }
        response = requests.post(
            "https://www.strava.com/api/v3/push_subscriptions",
            headers=headers,
            json=data,
        )
        app.logger.info(f"Webhook subscription response: {response.json()}")

        return "Preferences updated successfully!"

    # Retrieve current preferences from Firestore
    users_ref = db.collection("users")
    user_doc = users_ref.document(user_id).get()
    current_preferences = user_doc.to_dict().get("activities", [])

    # Display the form with checkboxes, pre-selecting the current preferences
    activities = [
        "AlpineSki",
        "BackcountrySki",
        "Badminton",
        "Canoeing",
        "Crossfit",
        "EBikeRide",
        "Elliptical",
        "EMountainBikeRide",
        "Golf",
        "GravelRide",
        "Handcycle",
        "HighIntensityIntervalTraining",
        "Hike",
        "IceSkate",
        "InlineSkate",
        "Kayaking",
        "Kitesurf",
        "MountainBikeRide",
        "NordicSki",
        "Pickleball",
        "Pilates",
        "Racquetball",
        "Ride",
        "RockClimbing",
        "RollerSki",
        "Rowing",
        "Run",
        "Sail",
        "Skateboard",
        "Snowboard",
        "Snowshoe",
        "Soccer",
        "Squash",
        "StairStepper",
        "StandUpPaddling",
        "Surfing",
        "Swim",
        "TableTennis",
        "Tennis",
        "TrailRun",
        "Velomobile",
        "VirtualRide",
        "VirtualRow",
        "VirtualRun",
        "Walk",
        "WeightTraining",
        "Wheelchair",
        "Windsurf",
        "Workout",
        "Yoga",
    ]
    form_html = """
        <h1>Which activities would you like to show?</h1>
        <form action="/preferences" method="post">
            {% for activity in activities %}
                <input type="checkbox" name="activity" value="{{ activity }}" {% if activity in current_preferences %}checked{% endif %}> {{ activity.capitalize() }}<br>
            {% endfor %}
            <input type="submit" value="Submit">
        </form>
    """
    return render_template_string(
        form_html, activities=activities, current_preferences=current_preferences
    )


# Webhook verification
@app.route("/webhook", methods=["GET"])
def verify_webhook():
    hub_mode = request.args.get("hub.mode")
    hub_verify_token = request.args.get("hub.verify_token")
    hub_challenge = request.args.get("hub.challenge")

    # Ensure the verify_token matches "STRAVA"
    if hub_mode == "subscribe" and hub_verify_token == "STRAVA":
        return {"hub.challenge": hub_challenge}, 200
    else:
        app.logger.error(f"Webhook verification failed: {hub_verify_token}")
        return {"error": "Invalid verify token"}, 400


# Webhook event receiver
@app.route("/webhook", methods=["POST"])
def handle_event():
    event = request.get_json()
    app.logger.info(f"Received event: {event}")
    if event.get("aspect_type") != "create":
        app.logger.info("Ignoring non-create event")
        return "", 200

    # Get the user ID from the event data
    user_id = str(
        event.get("owner_id")
    )

    if not user_id:
        app.logger.error("No user ID found in the event.")
        return jsonify({"error": "No user ID found"}), 400

    # Retrieve access token from Firestore
    user_doc = db.collection("users").document(user_id).get()
    if not user_doc.exists:
        app.logger.error(f"No user found in Firestore for ID: {user_id}")
        return jsonify({"error": "User not found"}), 400

    user_data = user_doc.to_dict()
    access_token = user_data.get("access_token")

    if not access_token:
        app.logger.error(f"Access token missing for user {user_id}")
        return jsonify({"error": "Access token missing"}), 400

    # Make request to fetch activity details
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(
        f"https://www.strava.com/api/v3/activities/{event['object_id']}",
        headers=headers,
    )
    activity = response.json()

    app.logger.info(f"Activity: {activity}")

    user_activities = user_data.get("activities", [])
    if activity["sport_type"] not in user_activities:
        updatable_activity = {
            "hide_from_home": True,
        }
        response = requests.put(
            f"https://www.strava.com/api/v3/activities/{event['object_id']}",
            headers=headers,
            json=updatable_activity,
        )
        app.logger.info(f"Activity of type {activity['sport_type']} muted")
    else:
        app.logger.info(f"Activity of type {activity['sport_type']} not muted")

    return "", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
