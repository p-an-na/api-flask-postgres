from flask import Flask, abort, request, jsonify, send_from_directory
from flask_jwt import jwt_required, JWT
from flask_marshmallow import Marshmallow
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_swagger_ui import get_swaggerui_blueprint
import apiClient
import authorization
from config_read import configReader
from error_messege import not_found, bad_request
from routes import request_api

app = Flask(__name__)
app.debug = True

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)
SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.yml'
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': 'Flask-Api'
    }
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)
app.register_blueprint(request_api.get_blueprint())
config = configReader()
app.secret_key = config['app']['secret_key']
app.config['SQLALCHEMY_DATABASE_URI'] = config['database']['db_endpoint']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)
ma = Marshmallow(app)

migrate = Migrate(app,db)

jwt = JWT(app, authorization.authenticate, authorization.identity)

@app.route('/ip/users', methods=['POST'])
def new_user():
    from models import UserModel
    username = request.json.get('username')
    password_hash = request.json.get('password')
    if username is None or password_hash is None:
        abort(400, 'Username or password is empty!')
    if UserModel.query.filter_by(username=username).first() is not None:
        abort(400, 'User has already exist.')
    user = UserModel(username=username, password_hash=password_hash)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201)

@app.route('/auth', methods=['POST'])
def login():
    username = request.json.get('username')
    password_hash = request.json.get('password')
    if not request.is_json or 'username' not in request.get_json() or 'password' not in request.get_json():
        return bad_request('The request data is not in JSON format')

@app.route('/protected/ip', methods=['POST'])
def create_ip():
    from models import IpModel
    if not request.is_json or 'ip_address' not in request.get_json() or 'country' not in request.get_json():
        return bad_request('The request data is not in JSON format')

    ip = IpModel(request.get_json()['ip_address'],request.get_json()['country'] )
    db.session.add(ip)

    return {'message': f'IP address: {ip.ip_address} has been created successfully.'}

@app.route('/protected/ip', methods=['GET'])
@jwt_required()
def get_ips():
  from models import IpModel, ip_schema
  all_ips = IpModel.query.all()
  result = ip_schema.dump(all_ips)
  return jsonify(result)


@app.route('/protected/ip/<ip_address>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def handle_ip(ip_address):
    from models import IpModel
    ip = IpModel.query.filter_by(ip_address=ip_address).first()

    if request.method == 'GET':
        if ip == None:
            response_get, status_code = apiClient.get_country(ip_address)
            if status_code != 500:
                country = response_get['country_name']
                ip_new = IpModel(ip_address=str(ip_address), country=str(country))
                db.session.add(ip_new)
                db.session.commit()
                return country
            if status_code == 500:
                return not_found('IP address is not correct')
        if ip != None:
            return ip.country
        else:
            return not_found("IP address does not exist")

    elif request.method == 'PUT':

        if not request.is_json or 'country' not in request.get_json():
            return bad_request('The request data is not in JSON format')
        ip = IpModel.query.filter_by(ip_address=ip_address).first()
        ip = IpModel(ip_address, request.get_json()['country'])
        db.session.commit()
        return {'message': f'IP address: {ip.ip_address} has been updated successfully.'}

    elif request.method == 'DELETE':
        if not ip:
            return not_found('404. Not found')
    db.session.delete(ip)
    db.session.commit()

    return jsonify({'message': f'IP address: {ip.ip_address} has been deleted successfully.'})

@app.route('/', methods=['GET'])
def index():
    return jsonify({'message': 'Hey, it is Restful API in Flask'})



if __name__ == "__main__":
    app.run(debug=True)