from flask import Flask, jsonify, request
from datetime import datetime, timedelta
from uuid import uuid4
from __main__ import app
from app import user_service
from app import project_service

"""
INTRO:
Usuários da API devem primeiramente obter um token de autorização para acesso.
Esta autorização é feita através da chamada ao endpoint: /api/auth.
Deve ser enviado o nome do usuário e a senha de acesso à aplicação
através do mecanismo de Basic Authentication do protocolo HTTP.
Se autorizado, a API retorna com um token temporário (validade de 30 minutos)
para ser utilizado pelo usuário nas chamadas posteriores à API.
"""

"""
Variables to indicate the current API version. 
"""
version_tag = '1.0'
version_url = 'v1'

"""
Store the list of generated tokens available for
 users to apply for API consuming
"""
running_tokens = {}

"""
Time to expire the token in naive token management
"""
token_expiration_time_in_secs = 60 * 30  # 30 minutes

api_datetime_format = '%Y/%m/%d %H:%M:%S'

@app.route('/api/version', methods=['GET'])
def api_version():
    info = {}
    info['app'] = 'Dashboard'
    info['version'] = version_tag
    info['url'] = '/api/{}'.format(version_url)
    return jsonify(info)


def apiv(json_dict):
    json_dict['api-version'] = version_url
    return json_dict

def return_json(result_dict, message_string, result_string):
    result_dict['result'] = result_string
    result_dict['datetime'] = datetime.now().strftime(api_datetime_format)
    result_dict['message'] = message_string
    return apiv(result_dict)


def return_json_fail(message):
    result = {}
    return jsonify(return_json(result, message, 'fail'))


def generate_new_token(tokens, credential):
    # check if there is already a previous token for the credential
    # delete it to have only one assigned to a credential
    tokens_to_delete = []
    for t in tokens:
        token = tokens[t]
        if credential == token['user'].email:
            tokens_to_delete.append(t)
    for t in tokens_to_delete:
        del tokens[t]
    return uuid4()


def check_if_token_is_valid(token_to_check, list_of_tokens):
    token_to_check = token_to_check.split(" ")
    if len(token_to_check) == 2:
        token_to_check = token_to_check[1]
    for token in list_of_tokens.values():
        if token_to_check == token['access-token']:
            if token['expire'] < datetime.now():
                return False, "Token is expired. Please, authenticate again.", None
            else:
                return True, None, token
    return False, "Invalid token.", None

@app.route('/api/debug/clear-tokens', methods=['GET'])
def api_debug_clear_tokens(tokens):
    tokens.clear()
    return jsonify("Tokens cleared."), 200


@app.route('/api/debug/list-tokens', methods=['GET'])
def api_debug_list_tokens():
    return jsonify(running_tokens), 200


@app.route('/api/auth', methods=['GET'])
def api_auth():
    #request.headers['']
    auth = request.authorization
    if auth is None:
        return return_json_fail('Authentication required. Provide username and password.'), 401

    # continue with login attempt
    user_email = auth.username
    user_passd = auth.password
    user = user_service.authenticate(user_email, user_passd)
    if user is None:
        return return_json_fail("Access denied for user: '{}'".format(user_email)), 401

    # if success on authenticating, create a new token and publish to the user
    new_token = generate_new_token(running_tokens, user.email)
    expire = datetime.now() + timedelta(seconds=token_expiration_time_in_secs)
    token_dict = {
        'access-token': str(new_token),
        'expire': expire,
        'user': user,
    }
    running_tokens[str(new_token)] = token_dict

    result_token_dict = {
        'result': "success",
        'access-token': str(new_token),
        'token-type': 'bearer',
        'expire': expire.strftime(api_datetime_format),
        'credential': user.email,
    }

    # return token
    return jsonify(apiv(result_token_dict)), 200


@app.route('/api/v1/ping', methods=['GET'])
def api_ping():
    return "pong"


@app.route('/api/v1/projects', methods=['GET'])
def api_projects():
    if 'Authorization' not in request.headers:
        return return_json_fail("Authorization bearer token was not provided."), 401

    access_token = request.headers['Authorization']

    success, message, token = check_if_token_is_valid(access_token, running_tokens)
    if not success:
        return return_json_fail(message), 401

    user = token['user']
    if user is None:
        return return_json_fail("Internal error. Current user not found."), 500

    owned_projects = project_service.get_all_owned_projects_of_user(user)
    if owned_projects is None:
        return return_json_fail("Fail to return owned project list."), 500
    granted_projects = project_service.get_all_granted_projects_of_user(user)
    if granted_projects is None:
        return return_json_fail("Fail to return owned project list."), 500

    projects = granted_projects
    for p in owned_projects:
        if p not in projects:
            projects.append(p)

    json = []
    for i in range(0, len(projects)):
        projects[i] = project_service.load_project_by_id(projects[i].id)
        json.append(projects[i].to_json())

    return jsonify({"projects":json}), 200


@app.route('/api/v1/dashboard/<project_id>', methods=['GET'])
def api_project_by_id(project_id):
    if 'Authorization' not in request.headers:
        return return_json_fail("Authorization bearer token was not provided."), 401

    access_token = request.headers['Authorization']

    success, message, token = check_if_token_is_valid(access_token, running_tokens)
    if not success:
        return return_json_fail(message), 401

    user = token['user']
    if user is None:
        return return_json_fail("Internal error. Current user not found."), 500

    project = project_service.find_project_by_id(project_id)
    if project is None:
        return return_json_fail("Project {} not found.".format(project_id)), 404

    project = project_service.load_project_by_id(project_id)

    return jsonify(project.to_json()), 200
