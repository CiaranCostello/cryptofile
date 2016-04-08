import pickle, argparse, Crypto, tornado
from tornado import httpclient
import requests
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import MD5
from cryptography.fernet import Fernet

#key size in bits
KEY_LENGTH = 1024

def fileFlag(subparser):
	required = subparser.add_argument_group('required arguments')
	required.add_argument('-c', '--config', required=True, help='yaml file describing the application')
	required.add_argument('-m', '--manager', required=True, help='sepcify the host and port of the docker manager eg 127.0.0.1:3000')
	required.add_argument('-q', '--quiet', required=False, help='Supress messages from the script')

#allows us to specify the command line arguments that the script must recieve in order to execute
def clargs():
	main_parser = argparse.ArgumentParser(description='a script to get a symetric key from an address or decode a file using a symetric key')
	
	sub_parser = main_parser.add_subparsers(dest='cmd')
	sub_parser.required = True
	#sub commands for the program
	init = sub_parser.add_parser('init', help='initialise in this directory. Creates and saves private and public keys')

	decrypt = sub_parser.add_parser('decrypt', help='decrypts a file with a symetric key')
	decrypt.add_argument('-f', '--fileName', required=True, help='file name to decrypt')

	getKey = sub_parser.add_parser('getKey', help='Requests a key from a web server')
	getKey.add_argument('-a', '--address', required=True, help='Address of web server to request the key from')
	getKey.add_argument('-u', '--username', required=True, help='Username')
	getKey.add_argument('-p', '--password', required=True, help='Password')

	pkey = sub_parser.add_parser('pkey', help='Prints out public key')

	ls = sub_parser.add_parser('ls', help='List of files in repository')

	pull = sub_parser.add_parser('pull', help='pull a file from the server')
	pull.add_argument('-f', '--fileName', required=True, help='file name to decrypt')

	return main_parser.parse_args()


class crypto():
	def __init__(self, generateKey=False):
		#get public and private key
		if generateKey:
			random_gen = Random.new().read
			self.keypair = RSA.generate(KEY_LENGTH, random_gen)
			self.init()
		else:
			fh = open('keypair', 'rb')
			self.keypair = RSA.importKey(fh.read())

	def init(self):
		#print public key
		print('Public Key: '+str(self.keypair.publickey()))
		#save keypair as file
		fh = open('keypair', 'wb')
		fh.write(self.keypair.exportKey())

	def decrypt(self, filename):
		#get symmetric key
		fh = open('sym_key', 'rb')
		key = fh.read()
		#open file
		fh = open(filename, 'rb')
		encrypted_file = fh.read()
		#decrypt file
		cipher_suite = Fernet(key)
		decrypted_file = cipher_suite.decrypt(encrypted_file)
		#write decrypted file
		fh = open(filename, 'wb')
		fh.write(decrypted_file)

	def getKey(self, address, username, password):
		#generate public key
		public_key = self.keypair.publickey()
		client = tornado.httpclient.HTTPClient()
		#encrypt details, username and password
		e_u, e_p = self.__encrypt_details()
		#send public key to handler to request symmetric key for bucket
		body_dict = {'pkey':pickle.dumps(public_key), 'password':e_p, 'username':e_u}
		body = pickle.dumps(body_dict)
		request = tornado.httpclient.HTTPRequest(method='POST', url=address+'/key', body=body)
		try:
			p = client.fetch(request)
		except httpclient.HTTPError as e:
			print("Error: "+ str(e))
		client.close()
		encrypted_key = pickle.loads(p.body)
		#decrypt response using private key
		key = self.keypair.decrypt(encrypted_key)

		#save key as file
		fh = open('sym_key', 'wb')
		fh.write(key)

	#prints out the public key
	def getPKey(self):
		public_key = self.keypair.publickey()
		print(public_key.exportKey())

	#sends request for list of filenames in repo
	def ls(self):
		#generate public key
		public_key = self.keypair.publickey()
		#send public key to handler with encrypted password and username to request file
		client = tornado.httpclient.HTTPClient()
		#generate body containing public key, username and password
		body = self.__details_key_body(public_key)
		#send request to the ls handler
		request = tornado.httpclient.HTTPRequest(method='POST', url=address+'/ls', body=body)
		try:
			p = client.fetch(request)
		except httpclient.HTTPError as e:
			print("Error: "+ str(e))
		client.close()
		#decrypt list using private key
		print(p.body)

	#pull a file from the repo, decrypt it and save in the directory
	#def pull(self, filename):


	def __encrypt_details(self):
		client = tornado.httpclient.HTTPClient()
		#get servers public key
		try:
			server_pubkey = RSA.importKey(client.fetch(address+'/pubkey').body)
		except httpclient.HTTPError as e:
			print("Error: " + str(e))
		#encrypt password and username
		e_p = server_pubkey.encrypt(password.encode('utf-8'), 32)[0]
		e_u = server_pubkey.encrypt(username.encode('utf-8'), 32)[0]
		return e_u, e_p

	def __details_key_body(self, pkey):
		e_u, e_p = self.__encrypt_details()
		body_dict = {'pkey':pickle.dumps(public_key), 'password':e_p, 'username':e_u}
		body = pickle.dumps(body_dict)
		return body


if __name__ == '__main__':
	args = clargs()
	if(args.cmd == 'init'):
		crypto(generateKey=True).init()
	elif(args.cmd == 'decrypt'):
		crypto().decrypt(args.fileName)
	elif(args.cmd == 'getKey'):
		crypto().getKey(args.address, args.username, args.password,)
	elif(args.cmd == 'pkey'):
		crypto().getPKey()
	elif(args.cmd == 'ls'):
		crypto().ls()
	elif(args.cmd == 'pull'):
		crypto().pull(args.fileName)
