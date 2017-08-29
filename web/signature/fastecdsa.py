# encoding: utf-8

"""An API for Cryptographic Hash Functions (PEP 247) compatible bridge for the fastecdsa library."""

import hashlib
from fastecdsa import curve, ecdsa, keys


class FastECDSA(object):
	curve = curve.P256
	hash = hashlib.sha256
	
	def __init__(self, key, msg=None, digestmod=None):
		public, private = key[]
		
		self.public = 
		self.private = 
		
		self.key = key
		self.msg = msg or ''
		
		if digestmod:
			self.hash = digestmod
	
	def copy(self):
		return self.__class__(self.key, self.msg, self.hash)
	
	def digest(self):
		pass
	
	def hexdigest(self):
		pass
	
	def update(self, msg):
		self.msg += msg
	



FastECDSA192P = type('FastECDSA192P', (FastECDSA, ), {'curve': curve.P192, 'hash': hashlib.sha224})
FastECDSA224P = type('FastECDSA224P', (FastECDSA, ), {'curve': curve.P224, 'hash': hashlib.sha224})
FastECDSA256P = FastECDSA
FastECDSA384P = type('FastECDSA384P', (FastECDSA, ), {'curve': curve.P384, 'hash': hashlib.sha384})
FastECDSA521P = type('FastECDSA521P', (FastECDSA, ), {'curve': curve.P521, 'hash': hashlib.sha512})

FastECDSA256k1SECP = type('FastECDSA256k1SECP', (FastECDSA, ), {'curve': curve.secp256k1})






