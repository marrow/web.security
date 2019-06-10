from ..security.keyring import Keyring


class SignatureExtension(object):
	provides = {'signature'}
	
	def __init__(self, keys=None):
		self.keyring = Keyring(keys)
	
	def start(self, context):
		self.keyring.start()
		context.signature = self.keyring
	
	def stop(self, context):
		del context.signature
		self.keyring.stop()
