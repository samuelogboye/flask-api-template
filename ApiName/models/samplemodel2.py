#!/usr/bin/env python3
"""Template for the SampleModelTwo Class"""
from ApiName import db
from ApiName.models.base import BaseModel
from ApiName.models.user import User


class SampleModelTwo(BaseModel):
        """Template for the SampleModelTwo Class"""
        __tablename__ = 'sample_model_twos'
        user_id = db.Column(db.String(255), db.ForeignKey('users.id'), nullable=False)
        rating = db.Column(db.Integer, nullable=False)
        comment = db.Column(db.String(1000), nullable=True)

        user = db.relationship('User', back_populates='sample_model_twos')


        def __init__(self, user_id, rating, comment=None):
                super().__init__()
                self.user_id = user_id
                self.rating = rating
                self.comment = comment

        def __repr__(self):
                return f'<SampleModelTwo {self.id}>'
        def format(self):
                return {
                                'id': self.id,
                                'user_id': self.user_id,
                                'rating': self.rating,
                                'comment': self.comment
                }