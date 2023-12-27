from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
#from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous.url_safe import URLSafeTimedSerializer as Serializer
from ApiName import db
from ApiName.models.user import User
from functools import wraps
from ApiName.emails import send_password_reset_email, send_otp_email, reset_password_otp
from ApiName.sms import send_otp_sms
from datetime import datetime, timedelta
from random import randint
from .auth_utils import login_required, admin_required
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, decode_token, get_jwt_identity, get_jwt, set_access_cookies, set_refresh_cookies, unset_jwt_cookies
from ApiName.util_routes import get_image_url

# Create a Blueprint for authentication routes
auth_bp = Blueprint('auth', __name__, url_prefix='/api/v1/auth')

# Endpoint for user registration
@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    required_fields = ['email', 'password', 'first_name', 'last_name', 'phone_number']
    if not all(field in data for field in required_fields):
        return jsonify({'message': 'Incomplete registration data'}), 400

    data['email'] = data['email'].lower()

    import re

    def is_valid_email(email):
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern, email) is not None

    if not is_valid_email(data['email']):
        return jsonify({'message': 'Invalid email'}), 400

    try:
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user:
            return jsonify({'message': 'Email already exists'}), 400

        new_user = User(
            email=data['email'],
            first_name=data['first_name'],
            last_name=data['last_name'],
            phone_number=data['phone_number'],
            password=generate_password_hash(data['password'])
        )
        new_user.insert()

        otp = str(randint(1000, 9999))
        otp_expiry = datetime.now() + timedelta(minutes=10)
        new_user.otp = otp
        new_user.otp_expiry = otp_expiry
        new_user.insert()

        full_name = f"{new_user.first_name} {new_user.last_name}"
        send_otp_email(full_name, new_user.email, otp)

        access_token = create_access_token(
            identity=new_user.id,
            expires_delta=timedelta(hours=1)
        )
        refresh_token = create_refresh_token(
            identity=new_user.id,
            expires_delta=timedelta(days=90)
        )

        userData = {
            "id": new_user.id,
            "email": new_user.email,
            "first_name": new_user.first_name,
            "last_name": new_user.last_name,
            "phone_number": new_user.phone_number,
            "email_confirmed": new_user.email_confirmed,
            "profile_picture": new_user.profile_picture,
            "is_active": new_user.is_active,
            "is_admin": new_user.is_admin,
            "accessToken": access_token,
            "refreshToken": refresh_token,
            "createdAt": new_user.createdAt,
            "updatedAt": new_user.updatedAt
        }
        return jsonify({'message': 'User registered. OTP sent to email for verification.', 'userData': userData}), 201
    except Exception as e:
        current_app.log_exception(exc_info=e)
        return (
            jsonify(
                {
                    "error": "Internal server error",
                    "message": "It's not you, it's us",
                    "status": False,
                }
            ),
            500,
        )

# Endpoint to confirm the OTP sent to the email
@auth_bp.route('/confirm_otp', methods=['POST'])
def confirm_otp():
    data = request.json

    if 'email' not in data or 'otp' not in data:
        return jsonify({'message': 'Incomplete data'}), 400

    user = User.query.filter_by(email=data['email']).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    otp = str(data['otp'])

    if not user.otp or user.otp != otp:
        return jsonify({'message': 'Invalid OTP'}), 400

    if datetime.now() > user.otp_expiry:
        return jsonify({'message': 'OTP expired'}), 400

    # OTP matches and is within the expiry time, confirm the email
    user.email_confirmed = True
    user.update()
    return jsonify({'message': 'Email confirmed successfully'}), 200

# Endpoint to resend OTP to the user's email
@auth_bp.route('/resend_otp', methods=['POST'])
def resend_otp():
    data = request.json
    if 'email' not in data:
        return jsonify({'message': 'Email is required to resend OTP'}), 400

    user = User.query.filter_by(email=data['email']).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    if user.email_confirmed:
        return jsonify({'message': 'Email already confirmed'}), 400

    # Generate a new OTP
    new_otp = str(randint(1000, 9999))  # Generate a new 6-digit OTP

    # Update the user's OTP in the database
    user.otp = new_otp
    otp_expiry = datetime.now() + timedelta(minutes=10)  # Set expiry time to 10 minutes from now
    user.otp_expiry = otp_expiry
    user.update()

    # Resend the OTP to the user's email (implement send_otp_email function)
    # Send the OTP to the user's email (implement send_otp_email function)
    full_name = user.first_name + " " + user.last_name
    send_otp_email(full_name, user.email, new_otp)

    return jsonify({'message': 'New OTP sent to email'}), 200

# Endpoint to send OTP to the user's email during password reset
@auth_bp.route('/password-reset-otp', methods=['POST'])
def password_reset_otp():
    data = request.json
    if 'email' not in data:
        return jsonify({'message': 'Email is required to resend OTP'}), 400

    user = User.query.filter_by(email=data['email']).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Generate a new OTP
    new_otp = str(randint(1000, 9999))  # Generate a new 6-digit OTP

    # Update the user's OTP in the database
    user.otp = new_otp
    otp_expiry = datetime.now() + timedelta(minutes=10)  # Set expiry time to 10 minutes from now
    user.otp_expiry = otp_expiry
    user.update()

    # Resend the OTP to the user's email (implement send_otp_email function)
    # Send the OTP to the user's email (implement send_otp_email function)
    full_name = user.first_name + " " + user.last_name
    reset_password_otp(full_name, user.email, new_otp)
    #send_otp_sms(otp=new_otp)

    return jsonify({'message': 'Password reset OTP sent to email'}), 200


# Endpoint for user login and token generation
@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    # Check if required fields are present in the request data
    if 'email' not in data or 'password' not in data:
        return jsonify({'message': 'Email and password are required'}), 400

    # turn email to lowercase
    data['email'] = data['email'].lower()

    user = User.query.filter_by(email=data['email']).first()
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid email or password'}), 401

    user.last_login = datetime.now()
    user.update()

    # Generate and return an authentication token for the user
    access_token = create_access_token(identity=user.id, expires_delta=timedelta(hours=1))   # Access token expires in 1 hour
    refresh_token = create_refresh_token(identity=user.id, expires_delta=timedelta(days=90))  # Refresh token expires in 24 hours

    response = jsonify({"msg": "login successful", "accessToken": access_token})
    set_access_cookies(response, access_token)
    return response, 200


# Endpoint for user logout
@auth_bp.route('/logout', methods=['POST'])
def logout():
    response = jsonify({"msg": "logout successful"})
    unset_jwt_cookies(response)
    return response

# Endpoint for token refresh
@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user_id = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user_id, expires_delta=timedelta(hours=1))
    return jsonify(access_token=new_access_token, message='Token refreshed successfully', user_data=User.query.get(current_user_id).format()), 200


# Endpoint to check if email exist in the database or not. Return True if it exist
@auth_bp.route('/check-email', methods=['POST'])
def check_email():
    data = request.get_json()
    email = data.get('email')

    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({'emailExists': True}), 200
    else:
        return jsonify({'emailExists': False}), 200


# Endpoint for password reset (after receiving the reset token)
@auth_bp.route('/confirm-reset-password', methods=['POST'])
def reset_password():
    data = request.json
    new_password = request.json.get('new_password')
    email = request.json.get('email')
    if not new_password or not email:
        return jsonify({'message': 'New password and email is required'}), 400

    user_check = User.query.filter_by(email=email).first()
    if not user_check:
        return jsonify({'message': 'User not found'}), 404

    # Update user's password with the new one
    user_check.password = generate_password_hash(new_password)
    db.session.commit()

    return jsonify({'message': 'Password reset successful'}), 200

# Endpoint for Password Change
@auth_bp.route('/change-password', methods=['PUT'])
@login_required
def change_password(user):
    data = request.json
    if 'old_password' not in data or 'new_password' not in data:
        return jsonify({'message': 'Old password and new password are required'}), 400
    if data['old_password'] == data['new_password']:
        return jsonify({'message': 'Old password and new password cannot be the same'}), 400
    if len(data['new_password']) < 6:
        return jsonify({'message': 'New password must be at least 6 characters long'}), 400
    if not check_password_hash(user.password, data['old_password']):
        return jsonify({'message': 'Invalid old password'}), 401
    user.password = generate_password_hash(data['new_password'])
    db.session.commit()
    return jsonify({'message': 'Password changed successfully'}), 200

# Endpoint for user profile
@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    user = get_jwt_identity()
    user = User.query.get(user)
    if not user:
        return jsonify({'message': 'User not found'}), 404

#     #Check the number of orders the user has placed
#     order = Order.query.filter_by(user_id=user.id).all()
#     order_count = len(order)
    userData = {
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'phone_number': user.phone_number,
        'profile_picture': user.profile_picture,
        'last_login': user.last_login,
        'house_address': user.house_address,
        'createdAt': user.createdAt,
        'updatedAt': user.updatedAt
    }
    return jsonify(userData)

# Endpoint for user profile update
@auth_bp.route('/profile', methods=['PUT'])
@login_required
def update_profile(user):
    try:
        if 'profile_picture' in request.files:
                profile_picture = request.files['profile_picture']
                user.profile_picture = get_image_url(profile_picture)
        user.house_address = request.form['house_address']
        user.first_name = request.form['first_name']
        user.last_name = request.form['last_name']
        user.phone_number = request.form['phone_number']
        user.update()

        return jsonify(user.format()), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error updating user profile: {e}")
        return str(e), 500

# Endpoint for user profile deletion
@auth_bp.route('/profile', methods=['DELETE'])
@admin_required
def delete_profile(user):
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'Profile deleted successfully'}), 200

# Endpoint to get all users
@auth_bp.route('/users', methods=['GET'])
@admin_required
def get_users(user):
    users = User.query.all()
    total = len(users)
    return jsonify([user.format() for user in users], "total_users:", total), 200

# Endpoint to get a user by ID
@auth_bp.route('/users/<user_id>', methods=['GET'])
def get_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    return jsonify(user.format()), 200

# Endpoint to update a user by ID
@auth_bp.route('/users/<user_id>', methods=['PUT'])
def update_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    data = request.json
    if 'email' in data:
        user.email = data['email']
    if 'first_name' in data:
        user.first_name = data['first_name']
    if 'last_name' in data:
        user.last_name = data['last_name']
    if 'username' in data:
        user.username = data['username']
    if 'password' in data:
        user.password = generate_password_hash(data['password'])
    db.session.commit()
    return jsonify(user.format()), 200

# Endpoint to delete a user by ID
@auth_bp.route('/users/<user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'}), 200


# Endpoint to make a user an admin
@auth_bp.route('/users/<user_id>/admin', methods=['PATCH'])
@login_required
def make_admin(user, user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    user.is_admin = True
    db.session.commit()
    return jsonify(user.format()), 200

import os
import json
import requests
from oauthlib.oauth2 import WebApplicationClient

# Configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

# OAuth2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

# Endpoint for Google login
@auth_bp.route("/google", methods=["GET"])
def google_login():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    print("Request URI:", request_uri)
    return jsonify({"redirect": request_uri})

# Endpoint for Google login callback
@auth_bp.route("/google/callback", methods=["GET"])
def google_callback():
    try:
        print("Google callback")
        # Get authorization code Google sent back to you
        code = request.args.get("code")

        # Find out what URL to hit to get tokens that allow you to ask for
        # things on behalf of a user
        google_provider_cfg = get_google_provider_cfg()
        token_endpoint = google_provider_cfg["token_endpoint"]

        # Prepare and send request to get tokens
        token_url, headers, body = client.prepare_token_request(
            token_endpoint,
            authorization_response=request.url,
            redirect_url=request.base_url,
            code=code
        )
        token_response = requests.post(
            token_url,
            headers=headers,
            data=body,
            auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
        )

        # Parse the tokens
        client.parse_request_body_response(json.dumps(token_response.json()))

        # Get user info from Google
        userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
        uri, headers, body = client.add_token(userinfo_endpoint)
        userinfo_response = requests.get(uri, headers=headers, data=body)

        # Check if user email is verified
        if userinfo_response.json().get("email_verified"):
            unique_id = userinfo_response.json()["sub"]
            users_email = userinfo_response.json()["email"]
            picture = userinfo_response.json()["picture"]
            users_name = userinfo_response.json()["given_name"]
        else:
            return jsonify({"error": "User email not available or not verified by Google."}), 400

        # Create a user with the info provided by Google
        user = User.query.filter_by(email=users_email).first()
        if not user:
            user = User(
                email=users_email,
                first_name=users_name[0],
                last_name=users_name[1],
                phone_number=+21000000000,
                profile_picture=picture,
                password=generate_password_hash("password"),
            )
            user.insert()
        # Login the user by returning them access token
        access_token = create_access_token(identity=user.id)
        print("Access token:", access_token)
        response = jsonify({"msg": "login successful", "accessToken": access_token})
        return response, 200
    except Exception as e:
        print(e)
        return jsonify({"error": "Failed to log in with Google."}), 400



