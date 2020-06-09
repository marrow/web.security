from binascii import unhexlify
from hashlib import md5, sha256
from hmac import compare_digest
from hmac import new as hmac
from os import getpid
from random import randint
from socket import getaddrinfo as _forward, gethostbyaddr as _reverse, gethostname, herror as DNSError
from threading import RLock
from time import time
from typing import Optional, Set

from cachetools.func import ttl_cache


log = __import__('logging').getLogger(__name__)

MACHINE = int(md5(gethostname().encode()).hexdigest()[:6], 16)


class SignatureError(ValueError):
	pass


class Counter:
	def __init__(self):
		self.value = randint(0, 2**24)
		self.lock = RLock()
	
	def __iter__(self):
		return self
	
	def __next__(self):
		with self.lock:
			self.value = (self.value + 1) % 0xFFFFFF
			value = self.value
		
		return value
	
	next = __next__

counter = Counter()


class DNS:
	TTL_ENTRIES: int = 128
	TTL_TIME: int = 60 * 60  # One hour.
	
	@staticmethod
	@ttl_cache(maxsize=TTL_ENTRIES, ttl=TTL_TIME)
	def resolve(host:str) -> Set[str]:
		"""Perform a cached forward DNS lookup.
		
		Retrieves the full set of identified IP addresses associated with the DNS name. This does not use
		`socket.gethostbyname` because there may be a pool of addresses associated with the rDNS name, not just one.
		
		Can generate statistics from live operation by calling the `cache_info` method:
		
			>>> DNS.resolve.cache_info()
			CacheInfo(hits=28, misses=16, maxsize=128, currsize=16)
		"""
		
		try:
			return {resolution[4][0] for resolution in _forward(host, 80)}
		except DNSError:
			return set()
	
	@staticmethod
	@ttl_cache(maxsize=TTL_ENTRIES, ttl=TTL_TIME)
	def reverse(addr:str) -> Optional[str]:
		"""Perform a cached reverse DNS lookup.
		
		Can generate statistics from live operation by calling the `cache_info` method:
		
			>>> DNS.reverse.cache_info()
			CacheInfo(hits=28, misses=16, maxsize=128, currsize=16)
		"""
		
		try:
			return _reverse(addr)[0]
		except DNSError:
			return None


class SessionIdentifier:
	def __init__(self, value=None):
		if value:
			self.parse(value)
		else:
			self.generate()
	
	def parse(self, value):
		self.time = int(value[:8], 16)
		self.machine = int(value[8:14], 16)
		self.process = int(value[14:18], 16)
		self.counter = int(value[18:24], 16)
	
	def generate(self):
		self.time = int(time())
		self.machine = MACHINE
		self.process = getpid() % 0xFFFF
		self.counter = next(counter)
	
	def __bytes__(self):
		return str(self).encode('ascii')
	
	def __str__(self):
		return f"{self.time:08x}{self.machine:06x}{self.process:04x}{self.counter:06x}"
	
	def __repr__(self):
		return f"{self.__class__.__name__}('{self}')"


class SignedSessionIdentifier(SessionIdentifier):
	__slots__ = ('__secret', '__signature', 'expires')
	
	def __init__(self, value=None, secret=None, expires=None):
		self.__secret = secret.encode('ascii') if hasattr(secret, 'encode') else secret
		self.__signature = None
		self.expires = expires
		
		super().__init__(value)
	
	def parse(self, value):
		if len(value) != 88:
			raise SignatureError("Invalid signed identifier length.")
		
		super().parse(value)
		
		self.__signature = value[24:].encode('ascii')
		
		if not self.valid:
			raise SignatureError("Invalid signed identifier.")
	
	@property
	def signed(self):
		return bytes(self) + self.signature
	
	@property
	def signature(self):
		if not self.__signature:
			self.__signature = hmac(
					self.__secret,
					unhexlify(bytes(self)),
					sha256
				).hexdigest()
			
			if hasattr(self.__signature, 'encode'):
				self.__signature = self.__signature.encode('ascii')
		
		return self.__signature
	
	@property
	def valid(self):
		if not self.__signature:
			raise SignatureError("No signature present.")
			return False
		
		if self.expires and (time() - self.time) > self.expires:
			raise SignatureError("Expired signature.")
			return False
		
		challenge = hmac(
				self.__secret,
				unhexlify(bytes(self)),
				sha256
			).hexdigest()
		
		if hasattr(challenge, 'encode'):
			challenge = challenge.encode('ascii')
		
		result = compare_digest(challenge, self.signature)
		
		if not result:
			raise SignatureError("Invalid signature:", repr(challenge), repr(self.signature))
			return False
		
		return True
