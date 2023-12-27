from flask import Blueprint, request, jsonify
from ApiName import db
from ApiName.db_utils import IdSchema
from ApiName.models.samplemodel1 import SampleModelOne
from uuid import UUID

sample_model_one_bp = Blueprint('sample_model_one', __name__, url_prefix='/api/v1/sample_model_one')


@sample_model_one_bp.route('/', methods=['GET'])
def get_menu_categories():
    pass