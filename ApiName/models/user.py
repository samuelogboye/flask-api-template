#!/usr/bin/env python3
"""Template for the User Class"""
from ApiName import db
from flask_login import UserMixin
from ApiName.models.base import BaseModel
from datetime import datetime


class User(UserMixin, BaseModel):
    __tablename__ = 'users'

    #id = db.Column(db.String(60), primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    first_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(500), nullable=False)
    phone_number = db.Column(db.String(20), nullable=True)
    email_confirmed = db.Column(db.Boolean, default=False)
    house_address = db.Column(db.String(500), nullable=True, default="")
    otp = db.Column(db.String(6), default=None)
    otp_expiry = db.Column(db.DateTime, default=None)
    profile_picture = db.Column(db.String(255), default='http://res.cloudinary.com/dbn9ejpno/image/upload/v1700666059/iuqjx3u5ts4tpvofhdnn.png')
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime, default=datetime.now())

    # Adding a one-to-many relationship with Review
    reviews = db.relationship('Review', backref='user_reviews', lazy=True)


    def __init__(self, email, first_name, last_name, password, phone_number, email_confirmed=False, otp=None, otp_expiry=None, house_address=None, profile_picture='http://res.cloudinary.com/dbn9ejpno/image/upload/v1700666059/iuqjx3u5ts4tpvofhdnn.png', is_active=True, is_admin=False, last_login=datetime.now()):
        super().__init__()
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.password = password
        self.phone_number = phone_number
        self.email_confirmed = email_confirmed
        self.otp = otp
        self.otp_expiry = otp_expiry
        self.profile_picture = profile_picture
        self.is_active = is_active
        self.is_admin = is_admin
        self.house_address = house_address
        self.last_login = last_login


    def __repr__(self):
        return f'<User {self.username}>'

    def format(self):
        return {
            'id': self.id,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'phone_number': self.phone_number,
            'house_address': self.house_address,
            'email_confirmed': self.email_confirmed,
            'profile_picture': self.profile_picture,
            'is_active': self.is_active,
            'is_admin': self.is_admin,
            'createdAt': self.createdAt,
            'updatedAt': self.updatedAt,
            'last_login': self.last_login
        }