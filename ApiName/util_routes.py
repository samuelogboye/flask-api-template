from flask import Blueprint, jsonify, send_file, request, url_for, send_from_directory, current_app, copy_current_request_context
from werkzeug.utils import secure_filename
from ApiName.auth.auth import login_required
import os
from ApiName import db
from dotenv import load_dotenv
import cloudinary.uploader
from ApiName.models.user import User
import threading

load_dotenv(".env")


util_bp = Blueprint('util', __name__)

@util_bp.route('/logs')
def get_logs():
    try:
        access_log_path = 'access_log.log'
        error_log_path = 'error_log.log'

        access_content = ''
        error_content = ''

        with open(access_log_path, 'r') as access_file:
            access_content = access_file.read()

        with open(error_log_path, 'r') as error_file:
            error_content = error_file.read()

        combined_content = f'Access Log:\n\n{access_content}\n\nError Log:\n\n{error_content}'

        return combined_content, 200, {'Content-Type': 'text/plain', 'Content-Disposition': 'attachment; filename=combined_logs.txt'}
    except FileNotFoundError:
        return "Log files not found", 404
    except Exception as e:
        return str(e), 500

# Route for cron job
@util_bp.route('/cron', methods=['GET'])
def cron_job():
    # Query the first user
    user = User.query.first()
    response = {'message': 'Everything is working fine', 'data': user.format()}
    return jsonify(response)


def get_image_url(file_to_upload):
    app = current_app
    try:
        #with app.app_context():
                current_app.logger.info('in upload route')
                cloudinary.config(cloud_name=os.getenv('CLOUD_NAME'), api_key=os.getenv('API_KEY'), api_secret=os.getenv('API_SECRET'))
                upload_result = cloudinary.uploader.upload(file_to_upload)
                current_app.logger.info(upload_result)

                picture_url = upload_result.get('url')
                return picture_url
                # print(f"Profile picture URL: {picture_url}")
                # user.profile_picture = picture_url
                # db.session.commit()
                # #user.update()
                # print("Profile picture updated")
    except Exception as e:
        print(f"Error uploading image: {e}")
        return {'msg': 'Request not sent', 'error': str(e)}



# def get_image_url(file_to_upload, user):
#     try:
#          thr = threading.Thread(
#             target=copy_current_request_context(get_image_url_cloudinary),
#             args=(file_to_upload, user)
#         )
#          thr.start()
#          print("Thread started")
#     except Exception as e:
#          return {'msg': 'Request not sent', 'error': str(e)}