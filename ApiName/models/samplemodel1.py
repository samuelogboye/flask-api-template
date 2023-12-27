#!/usr/bin/env python3
"""Template for the SampleModelOne Class"""
from ApiName import db
from ApiName.models.base import BaseModel


class SampleModelOne(BaseModel):
        """Template for the SampleModelOne Class"""
        __tablename__ = 'sample_model_ones'
        name = db.Column(db.String(255), nullable=False)
        description = db.Column(db.String(500), nullable=False)



        def __init__(self, name, description):
                super().__init__()
                self.name = name
                self.description = description

        def __repr__(self):
                return f'<SampleModelOne {self.id}>'

        def format(self):
                return {
                        'id': self.id,
                        'name': self.name,
                        'description': self.description
                }