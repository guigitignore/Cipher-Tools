#!python3

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from symetric_utils import SALT_LENGTH,deriv_master_key,deriv_passwd,hmac_secret
import sys
from symetric_utils import aes_decrypt_message

def decrypt_message(cipher:bytes,password:bytes)->bytes:
    if len(cipher)<SALT_LENGTH+AES.block_size+SHA256.digest_size:
        raise TypeError("Invalid size for data")

    indexIV=SALT_LENGTH+AES.block_size
    indexHMAC=len(cipher)-SHA256.digest_size

    salt=cipher[:SALT_LENGTH]
    iv=cipher[SALT_LENGTH:indexIV]
    hmac=cipher[indexHMAC:]

    cipher=cipher[indexIV:indexHMAC]
    
    kc,ki=deriv_master_key(deriv_passwd(password,salt))
    h=hmac_secret(ki,cipher,salt,iv)
    
    if h!=hmac:
        raise ValueError("HMAC is invalid")
    
    return aes_decrypt_message(cipher,kc,iv)

if __name__=="__main__":
    if len(sys.argv)!=4:
        print(f"Syntax {sys.argv[0]} <password> <input file> <output file>")
        sys.exit(-1)

    
    with open(sys.argv[2],"rb") as input_file,open(sys.argv[3],"wb") as output_file:
        password=sys.argv[1].encode()
        msg=input_file.read()
        result=decrypt_message(msg,password)
        output_file.write(result)