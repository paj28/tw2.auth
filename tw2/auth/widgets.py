import tw2.forms as twf, tw2.core as twc, webob, os, PBKDF2 as pbkdf2


@staticmethod
def pbkdf2_verify(password, hash):
    return hash == pbkdf2.crypt(password, hash)


class config(object):
    """
    Configuration variabels for tw2.auth.
    
    `user_object`
        The SQLAlchemy object for users. This must have a query attribute.
        (mandatory)
        
    `session_object`
        The SQLAlchemy object for sessions. This must have a query attribute.
        (mandatory)

    `user_name_field`
        The field on the user_object for the user name.
        (default: 'user_name')
    
    `password_field`
        The field on the user_object for the hashed password.
        (default: 'password')

    `sid_field`
        The field on the session_object for the session ID.
        (default: 'id')

    `user_relation`
        The name of the relation from session_object to user_object.
        (default: 'user')
    
    `hash`
        The function to hash a password. This takes (password) as an argument
        and returns the hash using a random salt.
        (default: pbkdf2.crypt)
        
    `verify`
        The function to verify a password. This takes (password, hash) as
        arguments and returns True or False.
        (default: pbkdf2_verify)
        
    `post_login`
        Options to webob.Response to return after a successful login.
        (default: dict(status=302, location='/'))

    `post_logout`
        Options to webob.Response to return after logout.
        (default: dict(status=302, location='/login'))
    
    `cookie_name`
        Name of session cookie
        (default: 'tw2.auth')
    
    `cookie_options`
        Cookie options. For SSL connections, recommended is {'secure':True, 'httponly':True}
        (default: {'httponly':True})
    """    
        
    user_name_field = 'user_name'
    password_field = 'password'
    sid_field = 'id'
    user_relation = 'user'
    hash = staticmethod(pbkdf2.crypt)
    verify = pbkdf2_verify
    post_login = dict(status=302, location='/')
    post_logout = dict(status=302, location='/login')
    cookie_name = 'tw2.auth'
    cookie_options = {'httponly': True}


@classmethod
def check_session(cls, req):
    sid = req.cookies.get(config.cookie_name)
    if not sid:
        return False
    session = config.session_object.query.get(sid)    
    twc.core.request_local()['session'] = session
    return session


def get_session():
    return twc.core.request_local()['session']

def get_user():
    return getattr(get_session(), config.user_relation)

def add_user(user_name, password, **options):
    kw = dict(options)
    kw[config.user_name_field] = user_name
    kw[config.password_field] = config.hash(password)
    config.user_object(**kw)
    config.user_object.query.session.commit()


class LoginValidator(twc.Validator):
    msgs = {
        'badlogin': 'Incorrect login details; please try again.',
    }
    def validate_python(self, value, state=None):
        user = config.user_object.query.filter_by(**{config.user_name_field: value['user_name']}).first()
        if user and config.verify(value['password'], getattr(user, config.password_field)):
            value['user'] = user
            return
        raise twc.ValidationError('badlogin', self)


class Login(twf.FormPage):
    title = "Login"
    _no_autoid = True

    class child(twf.TableForm):
        validator = LoginValidator()
        user_name = twf.TextField()
        password = twf.PasswordField()
        submit = twf.SubmitButton(value='Login')

    @classmethod
    def validated_request(cls, req, data):
        sid = os.urandom(16).encode('hex')
        config.session_object(**{config.sid_field: sid, config.user_relation:data['user']})
        res = webob.Response(**config.post_login)
        res.set_cookie(config.cookie_name, sid, **config.cookie_options)
        return res


class PasswordValidator(twc.Validator):
    msgs = {
        'badpassword': 'Incorrect password',
    }
    def validate_python(self, value, state=None):
        if config.verify(value, getattr(get_user(), config.password_field)):
            return
        raise twc.ValidationError('badpassword', self)


class ChangePassword(twf.FormPage):
    title = "Change password"
    _no_autoid = True

    class child(twf.TableForm):
        current_password = twf.PasswordField(validator=PasswordValidator())
        new_password = twf.PasswordField(validator=twc.Required)
        confirm_password = twf.PasswordField(validator=twc.MatchValidator(other_field='new_password'))

    @classmethod
    def validated_request(cls, req, data):
        setattr(get_user(), config.password_field, config.hash(data['new_password']))
        return webob.Response(**config.post_login)


class Logout(twc.Page):
    title = 'Logout'
    _no_autoid = True
    
    @classmethod
    def request(cls, req):
        sess = config.session_object.query.get(req.cookies.get(config.cookie_name))
        if sess:
            sess.query.session.delete(sess)
        res = webob.Response(**config.post_logout)
        res.set_cookie(config.cookie_name, '')
        return res
