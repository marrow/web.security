# encoding: utf-8

import hashlib, hmac

from binascii import hexlify, unhexlify
from os import urandom

from web.core.util import lazy
from web.security.csrf import CSRFToken, SignedCSRFToken, CSRFError


log = __import__('logging').getLogger(__name__)


class CSRFHandler(object):
    __slots__ = ('_ctx', 'ext')
    
    def __init__(self, context, csrf_ext):
        self._ctx = context
        self.ext = csrf_ext
    
    def __call__(self, token):
        if len(token) != 128:
            return False
        
        try:
            SignedCSRFToken(token, secret=self.user_secret.value)
        except CSRFError:
            return False
        return True
    
    def _generate(self):
        return SignedCSRFToken(secret=self.user_secret.value)
    
    def __str__(self):
        return str(self._generate())
        
    def __bytes__(self):
        return bytes(self._generate())
        
    @property
    def user_secret(self):
        context = self._ctx
        token = None
        try:
            if self.ext.cookie:
                cookie = context.request.cookies.get(self.ext.cookie['name'], None)
                if cookie: token = SignedCSRFToken(cookie, secret=self.ext._secret)
            else:
                token = context.session.csrf
        except CSRFError:
            log.warn("Could not verify CSRF cookie, generating new token", extra=dict(cookie=cookie))
        except AttributeError:
            log.warn("Could retrieve user CSRF token from session, generating new token")
        
        if token:
            return token
        log.warn("No token, generating new one")
            
        token = SignedCSRFToken(secret=self.ext._secret) if self.ext.cookie else CSRFToken()
            
        if self.ext.cookie:
            context.response.set_cookie(
                    value=token.signed,
                    **self.ext.cookie
                )
        else:
            context.session.csrf = token
        
        return token


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
        if cookie is not None and secret is None:
            if not __debug__:
                raise ValueError("A secret must be defined in production environments when using cookie storage.")
                
            secret = hexlify(urandom(64)).decode('ascii')
            log.warn("Generating temporary csrf secret", extra=dict(secret=secret))
                
        self._secret = secret
        
        if cookie: # We are going to use cookie storage
            self.needs = {'request'}
            self.cookie = cookie = cookie or dict()
            cookie.setdefault('name', 'csrftoken')
            cookie.setdefault('path', '/')
        else: # We are going to use session storage
            self.needs = {'session'}
            self.cookie = None
    
    def create_handler(self, context):
        return CSRFHandler(context,self)
    
    def start(self, context):
        context.csrf = lazy(self.create_handler, 'csrf')
        