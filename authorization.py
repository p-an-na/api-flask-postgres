from werkzeug.security import safe_str_cmp



def authenticate(username, password_hash):
    from models import UserModel
    user = UserModel.query.filter_by(username=username).first()
    if user and safe_str_cmp(user.password_hash.encode('utf-8'), password_hash.encode('utf-8')):
        return user

def identity(payload):
    from models import UserModel
    id = payload['identity']
    return UserModel.query.filter_by(id=id).first()