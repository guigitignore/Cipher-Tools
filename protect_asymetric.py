#!python3

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import sys
from symetric_utils import aes_encrypt_message

# this function computes the RSA signature
def pss_secret(privKey:RSA.RsaKey,seq:bytes,iv:bytes,cipher:bytes):
    sha256_ctx=SHA256.new()
    # add encrypted key
    sha256_ctx.update(seq)
    # add iv
    sha256_ctx.update(iv)
    # add ciphered text
    sha256_ctx.update(cipher)
    # init signature proccess
    pss_ctx=pss.new(privKey)
    # return signature
    return pss_ctx.sign(sha256_ctx)

# This function takes a message, a private key and a public key and return ciphered text.
# This function can raise errors
def encrypt_message(message:bytes,pubKey:RSA.RsaKey,privKey:RSA.RsaKey)->bytes:
    #generate random kc and iv
    kc=get_random_bytes(AES.key_size[2])
    iv=get_random_bytes(AES.block_size)

    # cipher kc and iv with RSA pub key
    pkcs1_oaep_ctx=PKCS1_OAEP.new(pubKey)
    seq=pkcs1_oaep_ctx.encrypt(kc+iv)

    # cipher text with aes
    cipher=aes_encrypt_message(message,kc,iv)

    #sign the file
    signature=pss_secret(privKey,seq,iv,cipher)

    #return all fields
    return seq+cipher+signature

def print_help():
    print("Usage:")
    print(f"Syntax {sys.argv[0]} <pubkey file> <privkey file> <input file> <output file>")

if __name__=="__main__":
    if len(sys.argv)!=5:
        print_help()
        sys.exit(-1)

    try:
        pubKey=RSA.import_key(open(sys.argv[1]).read())
        privKey=RSA.import_key(open(sys.argv[2]).read())
        data=open(sys.argv[3],"rb").read()
        result=encrypt_message(data,pubKey,privKey)
        open(sys.argv[4],"wb").write(result)
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        print_help()
        sys.exit(-1)

    