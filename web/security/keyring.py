"""A semi-secure external process keyring.

This allows storage (but not retrieval) of signing keys, by name, within an external process. Data may then be sent
for signing against a specific key. Theoretically, should the host application be compromised, your keys will remain
safe.
"""

from atexit import register, unregister
from binascii import hexlify, unhexlify
from hmac import compare_digest
from multiprocessing import Process, Pipe
from numbers import Number

from marrow.package.loader import load


def ringleader(queue, keys):
	keystore = dict(keys)
	
	while True:
		message = queue.recv()
		
		if not isinstance(message, tuple):
			continue
		
		if len(message) < 2:
			continue
		
		sequence, operation = message[:2]
		message = message[2:]
		
		if operation not in ('quit', 'register', 'sign', 'verify'):
			continue
		
		if operation == 'quit':
			break
		
		if operation == 'register':
			name, value = message
			keystore[name] = value
			continue
		
		if operation == 'unregister':
			keystore.pop(message[0])
			continue
		
		if operation == 'sign':
			name, algorithm, value = message
		elif operation == 'verify':
			name, algorithm, value, signature = message
		
		key = keystore.get(name, name if len(name) >= 32 else None)
		algorithm = load(algorithm, 'pep-247')  # Load the PEP 247-compatible keyed hashing algorithm.
		
		# Will usually be hmac:HMAC, can also be something like web.security.fastecdsa:P256.
		
		signer = algorithm(key, value)
		result = signer.digest()
		
		if operation == 'sign':
			queue.send((sequence, result))
			continue
		
		if hasattr(signer, 'verify'):
			result = signer.verify(value, signature)
			queue.send((sequence, result))
			continue
		
		result = compare_digest(signature, result)
		queue.send((sequence, result))
	
	queue.close()


class Keyring:
	def __init__(self, keys=None):
		self.queue, queue = Pipe()
		self.ringleader = Process(target=ringleader, args=(queue, keys if keys else ()))
		self.sequence = 0
	
	def start(self):
		self.ringleader.start()
		
		register(self.stop)
	
	def stop(self):
		unregister(self.stop)
		
		self.queue.send((0, 'quit'))
		self.ringleader.join()
		self.ringleader = None
	
	def register(self, name, key):
		sequence = self.sequence = self.sequence + 1
		self.queue.send((sequence, 'register', name, key))
	
	def deregister(self, name):
		sequence = self.sequence = self.sequence + 1
		self.queue.send((sequence, 'deregister', name))
	
	def sign(self, key, value, signer='hmac:HMAC'):
		if hasattr(value, 'encode'):
			value = value.encode('utf-8')
		
		sequence = self.sequence = self.sequence + 1
		
		self.queue.send((sequence, 'sign', key, signer, value))
		seq, signature = self.queue.recv()
		
		assert sequence == seq
		return signature
	
	def verify(self, key, value, signature, signer='hmac:HMAC'):
		if hasattr(value, 'encode'):
			value = value.encode('utf-8')
		
		sequence = self.sequence = self.sequence + 1
		
		self.queue.send((sequence, 'verify', key, signer, value, signature))
		seq, result = self.queue.recv()
		
		assert sequence == seq
		return result
	
	def token(self, *parts):
		def process():
			for part in parts:
				if isinstance(part, Number):
					yield ("%x" % part).encode('ascii')
				elif isinstance(part, str):
					yield hexlify(part)
				else:
					yield part.encode('utf-8')
		
		return b':'.join(process())
	
	def __del__(self):
		self.stop()
		
		super().__del__()
