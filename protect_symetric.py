#!python3

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from symetric_utils import SALT_LENGTH,deriv_master_key,deriv_passwd,hmac_secret,aes_encrypt_message
import sys

def encrypt_message(msg:bytes,password:bytes)->bytes:
    salt=get_random_bytes(SALT_LENGTH)
    iv=get_random_bytes(AES.block_size)

    kc,ki=deriv_master_key(deriv_passwd(password,salt))

    c=aes_encrypt_message(msg,kc,iv)
    h=hmac_secret(ki,c,salt,iv)

    return salt+iv+c+h

if __name__=="__main__":
    if len(sys.argv)!=4:
        print(f"Syntax {sys.argv[0]} <password> <input file> <output file>")
        sys.exit(-1)

    
    with open(sys.argv[2],"rb") as input_file,open(sys.argv[3],"wb") as output_file:
        password=sys.argv[1].encode()
        msg=input_file.read()
        result=encrypt_message(msg,password)
        output_file.write(result)