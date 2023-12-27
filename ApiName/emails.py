"""Emails module"""

from flask import url_for, render_template, current_app
from flask_mail import Message
from ApiName import mail
import threading



def send_password_reset_email(name, email, token):
    # Send a password reset email with the tokenized link
    reset_url = url_for('auth.reset_password', token=token, _external=True)
    msg = Message('Password Reset Request', recipients=[email])
    msg.body = f"Hi {name}, \n\nYou have requested to reset your password, click the following link: {reset_url} to reset your password. \n\nIf you did not request a password reset, please ignore this email. \n\n MedApp Team"
    mail.send(msg)




def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

def send_email(name, email, subject, template, template_data):
    try:
        with current_app.app_context():
                msg_title = subject
                sender = "noreply@app.com"
                msg = Message(msg_title, sender=sender, recipients=[email])
                msg.html = render_template(template, data=template_data)

                thr = threading.Thread(target=send_async_email, args=(current_app._get_current_object(), msg))
                thr.start()

    except Exception as e:
        return {'msg': 'Email not sent', 'error': str(e)}

# Sending password reset email
def reset_password_otp(name, email, otp):
    subject = 'Verification Code'
    template = 'email_otp.html'
    template_data = {
        'app_name': 'Foodie',
        'title': 'Password Reset OTP - Foodie',
        'body': 'PPlease use this verification code to reset your password',
        'name': name,
        'otp': otp
    }
    send_email(name, email, subject, template, template_data)

# Sending OTP for registration or password reset
def send_otp_email(name, email, otp):
    subject = 'Verification Code'
    template = 'email_otp.html'
    template_data = {
        'app_name': 'Foodie',
        'title': 'Registration Confirmation - Foodie',
        'body': 'Please use this verification code to confirm your registration',
        'name': name,
        'otp': otp
    }
    send_email(name, email, subject, template, template_data)

# Sending welcome email
def welcome_email(name, email):
    subject = 'Welcome to Foodie'
    template = 'welcome_email.html'
    template_data = {
        'app_name': 'Foodie',
        'title': 'Welcome to Foodie - Foodie',
        'body': 'Welcome to Foodie. Please use this verification code to confirm your registration',
        'name': name
    }
    send_email(name, email, subject, template, template_data)


