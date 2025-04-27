import sys, getopt, getpass
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util import Padding
from Crypto.Random import get_random_bytes

class EncryptionError(Exception):
    def __init__(self, err_msg):
        self.err_msg = err_msg

class Encryption:
    def __init__(self, pubkeyfile="pubkeyfile.pem", privkeyfile="privatekeyfile.pem"):
        self.pubkeyfile = pubkeyfile
        self.privkeyfile = privkeyfile
        self.inputfile = None
        self.outputfile = None
        self.DEBUG = True
        self.keysize = 2048
        self.AESkeysize = 256
        self.sign = True
        # TODO: Fix Hardcoded self.private_key_passphrase
        self.private_key_passphrase = '00000'
        self.tk = None
    
    def generate(self):
        pass

    def save_publickey(self, publickey):
        if not self.pubkeyfile:
            raise EncryptionError("Public key file not set.")
        with open(self.pubkeyfile, 'wb') as f:
            f.write(publickey.export_key(format='PEM'))
        
        if self.DEBUG:
            print(f"Public key saved to {self.pubkeyfile}")
    
    def load_publickey(self):
        with open(self.pubkeyfile, 'rb') as f:
            pub_key_str = f.read()
        try:
            return RSA.import_key(pub_key_str)
        except EncryptionError as Error:
            print(f"Error cannot import public key: {Error.err_msg}")
            sys.exit(1)
    
    def save_keypair(self, keypair):
        # passphrase = input('Enter a passphrase to protect the saved private key: ')
        passphrase = getpass.getpass('Enter a passphrase to protect the saved private key: ')
        if not self.privkeyfile:
            raise EncryptionError("Private key file not set.")
        with open(self.privkeyfile, 'wb') as f:
            f.write(keypair.export_key(format='PEM', passphrase=passphrase))

    def load_keypair(self):
        # passphrase = getpass.getpass('Enter a passphrase to decode the saved private key: ')
        if not self.privkeyfile:
            raise EncryptionError("Private key file not set.")
        with open(self.privkeyfile, 'rb') as f:
            keypairstr = f.read()
        try:
            return RSA.import_key(keypairstr, passphrase=self.private_key_passphrase)
        except ValueError:
            print('Error: Cannot import private key from file ' + self.privkeyfile)
        sys.exit(1)
    
    def generate_key_pair(self):
        keypair = RSA.generate(self.keysize)
        self.save_publickey(keypair.publickey())
        self.save_keypair(keypair)
    
    def encrypt(self, plaintext, message_header, sqn, rnd, perm_key, login = False):
        if not self.pubkeyfile:
            raise EncryptionError("Public key file not set.")
        pub_key = self.load_publickey()
        RSAcipher = PKCS1_OAEP.new(pub_key)
        
        symkey = self.tk if login else perm_key
        AEScipher = AES.new(symkey, AES.MODE_GCM, nonce=sqn+rnd)
        
 
        AEScipher.update(message_header)
        ciphertext, authtag = AEScipher.encrypt_and_digest(plaintext)
        encrypted_symkey = RSAcipher.encrypt(symkey)  

        hybrid_struct = {}
        hybrid_struct['aes_key'] = encrypted_symkey
        hybrid_struct['epd'] = ciphertext
        hybrid_struct['mac'] = authtag
        hybrid_struct['nonce'] = sqn+rnd
        return hybrid_struct
    
    def decrypt_sym_key(self, encsymkey):
        priv_key = self.load_keypair()
        RSAcipher = PKCS1_OAEP.new(priv_key)
        try:
            symkey = RSAcipher.decrypt(encsymkey)
            self.tk = symkey
        except ValueError:
            raise EncryptionError('Decryption of AES key failed')
        return symkey
    
    def decrypt_epd(self, ciphertext, msg_header, sqn, rnd, key, authtag):
        cipher = AES.new(key, AES.MODE_GCM, nonce=sqn+rnd)
        try:
            cipher.update(msg_header)
            plaintext = cipher.decrypt_and_verify(ciphertext, authtag)
        except (ValueError, KeyError):
            raise EncryptionError('Decryption failed or authentication tag mismatch')

        return plaintext


        
        