import os

from flask import Flask, jsonify, g
from flask_httpauth import HTTPBasicAuth

import config
from microflack_common.auth import generate_token
from microflack_common import requests

app = Flask(__name__)
config_name = os.environ.get('FLASK_CONFIG', 'dev')
app.config.from_object(getattr(config, config_name.title() + 'Config'))

basic_auth = HTTPBasicAuth()


@basic_auth.verify_password
def verify_password(nickname, password):
    """Password verification callback.
    Verification is done by sending a request to the users service.
    """
    if not nickname or not password:
        return False
    r = requests.get('/api/users/me', auth=(nickname, password))
    if r.status_code != 200:
        return False
    g.current_user = r.json()
    return True


@basic_auth.error_handler
def password_error():
    """Return a 401 error to the client."""
    # To avoid login prompts in the browser, use the "Bearer" realm.
    return (jsonify({'error': 'authentication required'}), 401,
            {'WWW-Authenticate': 'Bearer realm="Authentication Required"'})


@app.route('/api/tokens', methods=['POST'])
@basic_auth.login_required
def new_token():
    """
    Generate an access token for the user.
    This endpoint is requires basic auth with nickname and password.
    """
    return jsonify({'token': generate_token(g.current_user['id'])})


if __name__ == '__main__':
    app.run()
