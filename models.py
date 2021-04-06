from flask_jwt import current_identity

from app import db, ma


class IpModel(db.Model):
    __tablename__ = 'flask_api'
    id = db.Column(db.Integer, primary_key=True,  autoincrement=True)
    ip_address = db.Column(db.String(20), unique=True)
    country = db.Column(db.String(60))

    def __init__(self, ip_address, country):
        self.ip_address = ip_address
        self.country = country


class IpSchema(ma.Schema):
    class Meta:
        fields = ('id', 'ip_address', 'country')
ip_schema = IpSchema()
ip_schema = IpSchema(many=True)


class UserModel(db.Model):
    __tablename__ = 'apiusers'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128))

    def __init__(self, username, password_hash):
        self.username = username
        self.password_hash = password_hash

    def __str__(self):
        return "User(id='%s')" % self.id, '%s' % current_identity