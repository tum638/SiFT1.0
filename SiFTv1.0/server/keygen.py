import PublicKeyEncryption

if __name__ == '__main__':
    enc = PublicKeyEncryption.Encryption("pubkeyfile.pem", "privatekeyfile.pem")
    enc.generate_key_pair()







