import tornado, pickle
import tornado.ioloop
import tornado.web
import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import MD5
import os, uuid
from os import listdir
from cryptography.fernet import Fernet

__UPLOADS__ = "uploads/"
#dictionary with user name:password 
users = {'Ciaran':'I', 'Irwin':'poo'}
#key size in bits
KEY_LENGTH = 1024

#provides form and links to uploaded files
class Userform(tornado.web.RequestHandler):
    def get(self):
        files = listdir(__UPLOADS__)
        self.render("uploadform.html", files=files)

#handles uploaded files 
class Upload(tornado.web.RequestHandler):
    def post(self):
        fileinfo = self.request.files['filearg'][0]
        print("fileinfo is" + str(fileinfo))
        fname = fileinfo['filename']
        fh = open(__UPLOADS__ + fname, 'wb')
        #encrypt file
        cipher_suite = Fernet(key)
        encryptedFile = cipher_suite.encrypt(fileinfo['body'])
        #store at address specified by __UPLOADS
        fh.write(encryptedFile)
        self.finish(fname + " is uploaded!! Check %s folder" %__UPLOADS__)

#handles requests for symmetric key from client
class KeyRequests(tornado.web.RequestHandler):
    def post(self):
        pickled_dict = self.request.body
        body_dict = pickle.loads(pickled_dict)
        pubkey = pickle.loads(body_dict['pkey'])
        #decrypt password and username from body
        client_username = asym_key.decrypt(body_dict['username']).decode('utf-8')
        client_password = asym_key.decrypt(body_dict['password']).decode('utf-8')
        #if the username and password are in the users return key for bucket
        if users[client_username] is client_password:
            print('encrypting key: '+str(key))
            encrypted_key = pubkey.encrypt(key, 32)[0]
            p = pickle.dumps(encrypted_key)
            self.write(p)
        else:
            print('Public key not in group')

#return public key
class pubkey(tornado.web.RequestHandler):
    def get(self):
        pubkey = asym_key.publickey()
        self.write(pubkey.exportKey())

#returns list of files in uploads folder
class ls(tornado.web.RequestHandler):
    def get(self):
        #list of files
        files = listdir(__UPLOADS__)
        self.write(files)

#returns a selected file from the uploads folder
class pull(tornado.web.RequestHandler):
    def get(self):
        headers = self.request.headers
        filename = headers['filename']
        if filename in listdir(__UPLOADS__):
            fh = open(__UPLOADS__ + filename, 'rb')
            f = fh.read()
            self.write(f)

application = tornado.web.Application([
        (r"/", Userform),
        (r"/upload", Upload),
        (r"/files/(.*)",tornado.web.StaticFileHandler, {"path": r"./uploads"},),
        (r"/key", KeyRequests),
        (r"/pubkey", pubkey),
        (r"/ls", ls),
        ], debug=True)

#generate or load a symmetric key
def getKey():
    #if there is no key then generate one
    if "encryptionkey" not in listdir("."):
        k = Fernet.generate_key()
        fh = open("encryptionkey", 'wb')
        fh.write(k)
    #otherwise load it from the file
    else:
        fh = open("encryptionkey", 'rb')
        k = fh.read()
    return k

#generate asymmetric public/private key pair
def genAsymKey():
    random_gen = Random.new().read
    return RSA.generate(KEY_LENGTH, random_gen)

#get key as global variable
key = getKey()
asym_key = genAsymKey()

if __name__ == "__main__":
    application.listen(8888)
    tornado.ioloop.IOLoop.instance().start()