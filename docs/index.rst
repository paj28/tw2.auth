tw2.auth
========


Introduction
------------

tw2.auth is an authentication layer for ToscaWidgets 2 and SQLAlchemy. It aims to provide a "batteries included" authentication system.


Getting started
---------------

Note: this requires the experimental tw2.core branch available here:
http://github.com/paj28/tw2.core

Add the following to your model::

    import sqlalchemy as sa, tw2.auth as twa

    class Session(Base):
        __tablename__ = 'session'
        id = sa.Column(sa.String(), primary_key=True)
        user_name = sa.Column(sa.String(), sa.ForeignKey('user.name'))
        user = sa.orm.relationship('User')
    
    class User(Base):
        __tablename__ = 'user'
        name = sa.Column(sa.String(), primary_key=True)
        password = sa.Column(sa.String())
        def __unicode__(self):
            return self.name

    twa.config.session_object = Session
    twa.config.user_object = User

Your controller should look something like::

    import tw2.core as twc, tw2.auth as twa
    
    class Unauth(twc.Directory):
        login = twa.Login()
        # your unprotected widgets go here

    class Auth(twc.Directory):
        auth_check = twa.check_session
        # your protected widgets go here
        change_password = twa.ChangePassword()
        logout = twa.Logout()

Your start.py should look something like::

    twd.dev_server(host='0.0.0.0', port=80, repoze_tm=True,
        unauth_response=webob.Response(status=302, location='/login'))

To create a user, use interactive Python::

    >>> import myapp.model as db, tw2.auth as twa
    >>> twa.add_user('admin', 'password')

Inside a controller widget, you can access the current session or user with `twa.get_session()` and `twa.get_user()`.


Configuration
-------------

.. autoclass:: tw2.auth.config

**Passlib**

`passlib <http://packages.python.org/passlib/>`_ contains functions for a number of common password hashing schemes. For example, to use Unix DES hashing::

    from passlib.hash import des_crypt
    twa.config.hash = staticmethod(des_crypt.encrypt)
    twa.config.verify = staticmethod(des_crypt.verify)


Future plans
------------

 * Account lockouts - Captcha
 * Timeout
 * User registration
 * User management - needs concept of administrator
 * Forgotten password
 * Password strength validation
 * Authorization using groups
 * Zero shared state mode - cryptographic session id, instead of database table
 * CSRF protection
 * Social login
 * Better logging
