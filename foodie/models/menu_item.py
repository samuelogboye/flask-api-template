#!/usr/bin/env python3
"""Template for the MenuItem Class"""
from ApiName import db
from ApiName.models.base import BaseModel
from ApiName.models.samplemodel1 import MenuCategory



class MenuItem(BaseModel):
        """Template for the MenuItem Class"""
        __tablename__ = 'menu_items'
        name = db.Column(db.String(255), nullable=False)
        description = db.Column(db.String(500), nullable=False)
        price = db.Column(db.Float, nullable=False)
        menu_category_id = db.Column(db.String(255), db.ForeignKey('menu_categories.id'), nullable=False)
        image_url = db.Column(db.String(255), nullable=True)

        menu_category = db.relationship('MenuCategory', backref=db.backref('item_category', lazy=True))

        def __init__(self, name, description, price, menu_category_id, image_url=None):
                super().__init__()
                self.name = name
                self.description = description
                self.price = price
                self.menu_category_id = menu_category_id
                self.image_url = image_url

        def __repr__(self):
                return f'<MenuItem {self.id}>'
        def format(self):
                return {
                        'id': self.id,
                        'name': self.name,
                        'description': self.description,
                        'price': self.price,
                        'menu_category_id': self.menu_category_id,
                        'image_url': self.image_url
                }