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

    class Session(Base):
        __tablename__ = 'session'
        id = sa.Column(sa.String(), primary_key=True)
        user_name = sa.Column(sa.String(), sa.ForeignKey('users.user_name'))
        user = sao.relationship('User')
    
    class User(Base):
        __tablename__ = 'user'
        user_name = sa.Column(sa.String(), primary_key=True)
        password = sa.Column(sa.String())

    twa.config.session_object = Session
    twa.config.user_object = User

Your controller should look something like::

    import tw2.core as twc, tw2.auth as twa, model as db
    
    class Unauth(twc.Directory):
        login = twa.Login()
        # your unprotected controller methods here

    class Auth(twc.Directory):
        auth_check = twa.check_session
        # your protected controller methods here
        change_password = twa.ChangePassword()
        logout = twa.Logout()

Your start.py should look something like::

    twd.dev_server(host='0.0.0.0', port=80, repoze_tm=True,
        unauth_response=webob.Response(status=302, location='/login'))

To create a user, use interactive Python::

    >>> import myapp.model as db, tw2.auth as twa
    >>> twa.add_user('admin', 'password')


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

 * Brute force lockouts
 * Timeout
 * Autocomplete=off
 * User registration
 * Forgotten password
 * Password strength validation
 * Authorization using groups