import hashlib, hmac

from binascii import hexlify
from os import urandom
from functools import partial

from web.core.util import lazy

from web.security.csrf import CSRFToken, SignedCSRFToken


log = __import__('logging').getLogger(__name__)


from web.security.csrf import CSRFError


class CSRFHandler(object):
    __slots__ = ('_ctx')
    
    def __init__(self, context):
        self._ctx = context
        
    def _get_user_secret(self):
        return self._ctx.user_csrf.__str__()
        
    def verify(self, token):
        try:
            SignedCSRFToken(value=token, secret=self._get_user_secret())
        except CSRFError:
            return False
        return True
        
    def generate_token(self):
        return SignedCSRFToken(secret=self._get_user_secret())
    
    # Potentially forward getattr? Does that work?
    def __str__(self):
        return self.generate_token().signed.decode('utf-8')


class CSRFExtension(object):
    """CSRF Protection extension.
    
    This extension offers a process of CSRF protection for forms within an application. It creates 
    a `context.csrf` object (see `CSRFHandler`) containing the methods needed to get a new token 
    or verify an existing one.
    """
    provides = {'csrf'}
    
    def __init__(self, use_session=True, secret=None, cookie=None):
        """Configre CSRF extension
        
        The first positional argument, `use_session`, determines whether the user's csrf token will be 
        stored using a cookie or in the user's session.
        
        `secret` is used to generate an HMAC signature of the random user token when using cookies. 
        The `secret` is not required when `use_session` is `False`.
        
        `cookie` will be passed to the WebOb `response.set_cookie` helper when `use_session` is `False`.
        """
        if use_session is False and secret is None:
            if not __debug__:
                raise ValueError(
                        "A secret must be defined in production environments when using cookie storage."
                    )
                
            secret = hexlify(urandom(64)).decode('ascii')
            log.warn("Generating temporary csrf secret", extra=dict(secret=secret))
                
        self.__secret = secret
        self._use_session = use_session
        
        if use_session: # We are going to use session storage
            self.needs = {'session'}
        else: # We are going to use cookie storage
            self.needs = {'request'}
            self.cookie = cookie = cookie or dict()
            cookie.setdefault('name', 'csrftoken')
            cookie.setdefault('path', '/')
        
    def get_user_csrf(self, context):
        token = None
        cookie = ""
        try:
            if self._use_session:
                token = CSRFToken(context.session.csrf) 
            else:
                cookie = context.request.cookies.get(self.cookie['name'], None)
                if cookie: token = SignedCSRFToken(cookie, secret=self.__secret)
        except CSRFError:
            log.warn("Could not verify CSRF cookie, generating new token", extra=dict(cookie=cookie))
        except AttributeError:
            log.warn("Could retrieve user CSRF token from session, generating new token")
        
        if token:
            return token
        
        context.user_csrf_new = True    
        return CSRFToken() if self._use_session else SignedCSRFToken(secret=self.__secret)
        
    def start(self, context):
        context.user_csrf = lazy(self.get_user_csrf, 'user_csrf')
    
    def prepare(self, context):
        # Set the context.csrf object
        context.csrf = CSRFHandler(context=context)
        
    def after(self, context):
        # Check the context.csrf object if a new user token has been created
        # If so, store it, either in the session or with response.set_cookie
        
        if hasattr(context, 'user_csrf_new'):
            if self._use_session:
                context.session.csrf = context.user_csrf.__str__()
            else:
                context.response.set_cookie(
                        value=context.user_csrf.signed,
                        **self.cookie
                    )
        