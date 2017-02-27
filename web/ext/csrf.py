import hashlib, hmac

from binascii import hexlify
from os import urandom

from web.core.util import lazy
from web.security.csrf import CSRFToken, SignedCSRFToken, CSRFError


log = __import__('logging').getLogger(__name__)


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
    
    def __str__(self):
        return self.generate_token().signed.decode('utf-8')


class CSRFExtension(object):
    """CSRF Protection extension.
    
    This extension offers a process of CSRF protection for forms within an application. It creates 
    a `context.csrf` object (see `CSRFHandler`) containing the methods needed to get a new token 
    or verify an existing one.
    """
    provides = {'csrf'}
    
    def __init__(self, cookie=None, secret=None):
        """Configre CSRF extension
        
        `cookie` will be passed to the WebOb `response.set_cookie` helper when. If cookie is None, then the extension 
        will use session based storage instead(prefered)
        
        `secret` is used to generate an HMAC signature of the random user token when using cookies. 
        The `secret` is not required when using session based storage.
        """
        if cookie is None and secret is None:
            if not __debug__:
                raise ValueError("A secret must be defined in production environments when using cookie storage.")
                
            secret = hexlify(urandom(64)).decode('ascii')
            log.warn("Generating temporary csrf secret", extra=dict(secret=secret))
                
        self.__secret = secret
        
        if cookie: # We are going to use cookie storage
            self.needs = {'request'}
            self.cookie = cookie = cookie or dict()
            cookie.setdefault('name', 'csrftoken')
            cookie.setdefault('path', '/')
        else: # We are going to use session storage
            self.needs = {'session'}
            self.cookie = None
    
    def get_user_csrf(self, context):
        token = None
        cookie = ""
        try:
            if self.cookie:
                cookie = context.request.cookies.get(self.cookie['name'], None)
                if cookie: token = SignedCSRFToken(cookie, secret=self.__secret)
            else:
                token = CSRFToken(context.session.csrf) 
        except CSRFError:
            log.warn("Could not verify CSRF cookie, generating new token", extra=dict(cookie=cookie))
        except AttributeError:
            log.warn("Could retrieve user CSRF token from session, generating new token")
        
        if token:
            return token
        
        context.user_csrf_new = True    
        return SignedCSRFToken(secret=self.__secret) if self.cookie else CSRFToken()
    
    def start(self, context):
        context.user_csrf = lazy(self.get_user_csrf, 'user_csrf')
    
    def prepare(self, context):
        context.csrf = CSRFHandler(context=context)
    
    def after(self, context):
        if hasattr(context, 'user_csrf_new'):
            if self.cookie:
                context.response.set_cookie(
                        value=context.user_csrf.signed,
                        **self.cookie
                    )
            else:
                context.session.csrf = context.user_csrf.__str__()
        