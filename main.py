#
#   Author: Pramit Patel
#   Date:
#   Description: Profolio Project
#---------------------------------------------------------
# Gcloud Link: https://patepramportfoliofinale.ue.r.appspot.com
#---------------------------------------------------------
# Partial code adaptation from MODULE 6 main.py for Handling files using FLASK

import io
import os
import uuid
import requests

from dotenv import load_dotenv
from flask import Flask, request, jsonify, send_file
from google.cloud import datastore, storage
from google.cloud.datastore.query import PropertyFilter
from jose import jwt

load_dotenv('oauth.env')
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key')

# Datastore and Storage Setup
client = datastore.Client()
storage_client = storage.Client()

# AUTH0 Configuration
CLIENT_ID = os.environ.get('AUTH0_CLIENT_ID')
CLIENT_SECRET = os.environ.get('AUTH0_CLIENT_SECRET')
DOMAIN = os.environ.get('AUTH0_DOMAIN')
ALGORITHMS = ["RS256"]
GCLOUD_BUCKET = os.environ.get('GCS_BUCKET_NAME')

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

# Error handler
@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Global Error Handling Messages
ERR_INVALID = {"Error": "The request body is invalid"}
ERR_UNAUTH = {"Error": "Unauthorized"}
ERR_NOPERMISSION = {"Error": "You don't have permission on this resource"}
ERR_NOTFOUND = {"Error": "Not found"}
ERR_INVALIDINSTRUCTOR = {"Error": "The value of instructor_id is invalid"}
ERR_INVALIDENROLLMENT = {"Error": "Enrollment data is invalid"}


#---------------------------------------------------------------
# REST API IMPLEMENTATION
#---------------------------------------------------------------
# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        if len(auth_header) < 2 or auth_header[0].lower() != 'bearer':
            raise AuthError(ERR_UNAUTH, 401)
        token = auth_header[1]
    else:
        raise AuthError(ERR_UNAUTH, 401)

    jwks = requests.get("https://" + DOMAIN + "/.well-known/jwks.json").json()
    try:
        unverified_header = jwt.get_unverified_header(token)
    except Exception:
        raise AuthError(ERR_UNAUTH, 401)

    if unverified_header.get("alg") == "HS256":
        raise AuthError(ERR_UNAUTH, 401)

    rsa_key = {}
    for key in jwks["keys"]:
        if key.get("kid") == unverified_header.get("kid"):
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except Exception:
            raise AuthError(ERR_UNAUTH, 401)

        return payload
    else:
        raise AuthError(ERR_UNAUTH, 401)


@app.route('/', methods=['GET'])
def index():
    return "Welcome to the main course page", 200

# -------------------------------------------------------
# HELPER FUNCTIONS
# -------------------------------------------------------
# Helper function
def get_user_by_sub_helper(sub):
    query = client.query(kind='users')
    query.add_filter(filter=PropertyFilter('sub', '=', sub))
    results = list(query.fetch())
    return results[0] if results else None

# Helper function to delete any old avatars
def delete_old_avatar(user_entity):
    old_avatar = user_entity.get('avatar_file')
    if old_avatar:
        cloud_bucket = storage_client.bucket(GCLOUD_BUCKET)
        old_file = cloud_bucket.blob(old_avatar)
        if old_file.exists():
            old_file.delete()

# Helperr funtion to look up user by datastore ID
def get_user_helper(user_id):
    user_key = client.key('users', user_id)
    return client.get(user_key)

# Helper fuciton to lookup a course by datstore ID


# -------------------------------------------------------
# Endpoints for API SPEC
# -------------------------------------------------------
# Endpoint 1 - User Login (POST) - Precreated Auth0 users
@app.route('/users/login', methods=['POST'])
def login():
    data_content = request.get_json(silent=True)

    if not data_content or 'username' not in data_content or 'password' not in data_content:
        return jsonify(ERR_INVALID), 400

    if not isinstance(data_content['username'], str) or not isinstance(data_content['password'], str):
        return jsonify(ERR_INVALID), 400

    user_body = {
        'grant_type': 'password',
        'username': data_content['username'],
        'password': data_content['password'],
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=user_body, headers=headers)

    if r.status_code != 200:
        return jsonify(ERR_UNAUTH), 401

    resp_data = r.json()
    return jsonify({'token': resp_data['id_token']}), 200


# Endpoint 2  - Get all Users (GET) - Admin
@app.route('/users', methods=['GET'])
def get_all_users():
    token = verify_jwt(request)
    users = get_user_by_sub_helper(token.get('sub'))

    if not users or users.get('role') != 'admin':
        return jsonify(ERR_NOPERMISSION), 403

    user_query = client.query(kind='users')
    users_list = []

    for all_users in user_query.fetch():
        users_list.append({
            'id': all_users.key.id,
            'role': all_users.get('role'),
            'sub': all_users.get('sub')
        })

    return jsonify(users_list), 200


# Endpoint 3 - Get A User (GET) - ADMIN or User with Matching JWT
@app.route('/users/<int:user_id>', methods=['GET'])
def get_a_user(user_id):
    # Token verification and fetches the users records from datastore
    token = verify_jwt(request)
    users = get_user_by_sub_helper(token.get('sub'))

    # Looks up the user enitty in datastore
    get_the_user = get_user_helper(user_id)

    # Validation check to cehck if user exists
    if not users or not get_the_user:
        return jsonify(ERR_NOPERMISSION), 403

    # Validation check 2 for role needed for peromissions for admin or user themselves
    if users.get('role') != 'admin' and users.key.id != get_the_user.key.id:
        return jsonify(ERR_NOPERMISSION), 403

    # JSON reponse properties
    user_details = {
        "id": get_the_user.key.id,
        "role": get_the_user.get('role'),
        "sub": get_the_user.get('sub')
    }
    # If the user is found includes the avatar url property to grab avatar for user
    if get_the_user.get('avatar_url'):
        user_details['avatar_url'] = get_the_user.get('avatar_url')

    # If the user is instructor or student it must include the courses as well
    if get_the_user.get('role') in ('instructor', 'student'):
        user_details['courses'] = get_the_user.get('courses', [])

    return jsonify(user_details), 200

# Endpoint 4  - Create/Update a user's avatar (POST) - Matching JWT ID
@app.route('/users/<int:user_id>/avatar', methods=['POST'])
def create_update_user(user_id):
    # validation check for files
    if 'file' not in request.files:
        return jsonify(ERR_INVALID), 400

    avatar_file = request.files['file']
    if avatar_file.filename == '':
        return jsonify(ERR_INVALID), 400

    # token verification
    token = verify_jwt(request)
    users = get_user_by_sub_helper(token.get('sub'))

    # User Lookup
    get_the_user = get_user_helper(user_id)

    # Validation check to see if there is a valid JWT that belongs to user id
    if not users or not get_the_user or users.key.id != get_the_user.key.id:
        return jsonify(ERR_NOPERMISSION), 403

    delete_old_avatar(get_the_user)

    cloud_bucket = storage_client.bucket(GCLOUD_BUCKET)

    cloud_bucket = storage_client.bucket(GCLOUD_BUCKET)
    new_avatar = f"{uuid.uuid4()}.png"

    new_file = cloud_bucket.blob(new_avatar)
    avatar_file.seek(0)
    new_file.upload_from_file(avatar_file, content_type='image/png')

    # Save file name and avatar url to the user in datastore
    avatar_url = f"{request.host_url.rstrip('/')}/users/{user_id}/avatar"
    get_the_user['avatar_file'] = new_avatar
    get_the_user['avatar_url'] = avatar_url
    client.put(get_the_user)

    return jsonify({'avatar_url': avatar_url}), 200

# Endpoint 5 - Get users avatar (GET) - Matching JWT ID
@app.route('/users/<int:user_id>/avatar', methods=['GET'])
def get_user_avatars(user_id):

    # Verify token
    token = verify_jwt(request)
    users = get_user_by_sub_helper(token.get('sub'))

    # User lookup
    get_the_user = get_user_helper(user_id)

    # Validaiton check to ensure there is a valid JWT
    if not users or not get_the_user or users.key.id != get_the_user.key.id:
        return jsonify(ERR_NOPERMISSION), 403

    # validaiton cehck if the user has an avatar saved
    avatar_name = get_the_user.get('avatar_file')
    if not avatar_name:
        return jsonify(ERR_NOTFOUND), 404

    # Verifies if the avtar file exists in the GCLOUD storage
    cloud_bucket = storage_client.bucket(GCLOUD_BUCKET)
    avatar_blob = cloud_bucket.get_blob(avatar_name)
    if not avatar_blob:
        return jsonify(ERR_NOTFOUND), 404


    # Download the avatar file
    file_obj = io.BytesIO()
    avatar_blob.download_to_file(file_obj)
    file_obj.seek(0)

    return send_file(file_obj, mimetype='image/png', download_name=avatar_name), 200

# Endpoint 6 - Delete a User's Avatar - Matching JWT ID
@app.route('/users/<int:user_id>/avatar', methods=['DELETE'])
def delete_user_avatar(user_id):
    # Verify Token
    token = verify_jwt(request)
    users = get_user_by_sub_helper(token.get('sub'))

    # User lookup
    get_the_user = get_user_helper(user_id)

    # Validation check to ensure valid JWT for user
    if not users or not get_the_user or users.key.id != get_the_user.key.id:
        return jsonify(ERR_NOPERMISSION), 403

    if not get_the_user.get('avatar_file'):
        return jsonify(ERR_NOTFOUND), 404

    # Delete old avatars
    delete_old_avatar(get_the_user)
    get_the_user.pop('avatar_file', None)
    get_the_user.pop('avatar_url', None)
    client.put(get_the_user)

    return '', 204

# Endpoint 7 - Create a course - ADMIN
@app.route('/courses', methods=['POST'])
def create_course():
    # Verfication
    token = verify_jwt(request)
    users = get_user_by_sub_helper(token.get('sub'))


    # validation check
    if not users or users.get('role') != 'admin':
        return jsonify(ERR_NOPERMISSION), 403

    data_content = request.get_json(silent=True)
    course_elements = ('subject','number', 'title','term', 'instructor_id')
    if not data_content or not all (field in data_content for field in course_elements):
        return jsonify(ERR_INVALID), 400

    instructor_id = data_content.get('instructor_id')
    if not isinstance(instructor_id, int):
        return jsonify(ERR_INVALID), 400

    instructor = get_user_helper(instructor_id)
    if not instructor or instructor.get('role') != 'instructor':
        return jsonify(ERR_INVALID), 409

    new_course = datastore.Entity(key=client.key('courses'))
    new_course.update({
        'subject': data_content.get('subject'),
        'number': data_content.get('number'),
        'title': data_content.get('title'),
        'term': data_content.get('term'),
        'instructor_id': instructor_id,
        'students': []
    })
    client.put(new_course)



# Endpoint 8 - Get all courses (GET)

# Endpoint 9 - Get a course (GET)

# Endpoint 10 - Update a course (PATCH) - ADMIN

# Endpoint 11 - Delete a course (DELETE) - ADMIN

# Endpoint 12 - Update Enrollment (Patch) - Admin or instructor

# Endpoint 13 - Get enrollment for a course (GET) - Admin or instructor



if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

