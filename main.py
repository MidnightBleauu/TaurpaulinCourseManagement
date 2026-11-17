#
#   Author: Pramit Patel
#   Date:
#   Description: Profolio Project
#---------------------------------------------------------
# Gcloud Link: https://patepramportfoliofinale.ue.r.appspot.com
#---------------------------------------------------------

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

# HELPER FUNCTIONS
def get_user_by_sub_helper(sub):
    query = client.query(kind='users')
    query.add_filter(filter=PropertyFilter('sub', '=', sub))
    results = list(query.fetch())
    return results[0] if results else None


# Endpoints for API SPEC
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



# Endpoint 4  - Create/Update a user's avatar (POST) - Matching JWT ID


# Endpoint 5 - Get users avatar (GET) - Matching JWT ID


# Endpoint 6 - Delete a User's Avatar - Matching JWT ID


# Endpoint 7 - Create a course - ADMIN

# Endpoint 8 - Get all courses (GET)

# Endpoint 9 - Get a course (GET)

# Endpoint 10 - Update a course (PATCH) - ADMIN

# Endpoint 11 - Delete a course (DELETE) - ADMIN

# Endpoint 12 - Update Enrollment (Patch) - Admin or instructor

# Endpoint 13 - Get enrollment for a course (GET) - Admin or instructor



if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

