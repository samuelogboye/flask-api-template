#!/usr/bin/env python3
"""
Base template for the Event driven application
"""
from ApiName import db
from uuid import uuid4
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime


def get_uuid():
    """Generate a unique id using uuid4()"""
    return uuid4().hex


# Create a base model class that will contain common functionality
class BaseModel(db.Model):
    """BaseClass for all models"""

    # Make this class abstract so it won't be mapped to a database table
    __abstract__ = True

    # Define a primary key column with a default value of a generated UUID
    id = db.Column(db.String(255), primary_key=True, unique=True, nullable=False)
    createdAt = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(), nullable=False)
    updatedAt = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())


    def __init__(self, *args, **kwargs):
      super().__init__(*args, **kwargs)
      self.id = get_uuid() if not self.id else self.id  # Generate UUID if not provided
      self.createdAt = datetime.now()
      self.updatedAt = datetime.now()

    def insert(self):
        """Insert the current object into the database"""
        db.session.add(self)
        db.session.commit()

    def update(self):
        """Update the current object in the database"""
        self.updatedAt = datetime.now()
        db.session.commit()

    def delete(self):
        """Delete the current object from the database"""
        db.session.delete(self)
        db.session.commit()

    def format(self):
        """Format the object's attributes as a dictionary"""
        # This method should be overridden in subclasses
        raise NotImplementedError(
            "Subclasses must implement the 'format' method"
        )