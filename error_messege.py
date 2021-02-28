from flask import jsonify


def bad_request(message):
    response = jsonify({'error': message})
    response.status_code = 400
    return response


def not_found(message):
    response = jsonify({'error': message})
    response.status_code = 404
    return response