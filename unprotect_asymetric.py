#!python3

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
import sys
from symetric_utils import aes_decrypt_message

def decrypt_message(cipher:bytes,pubKey:RSA.RsaKey,privKey:RSA.RsaKey)->bytes:
    if len(cipher)<SHA256.digest_size+privKey.size_in_bytes():
        raise ValueError("Invalid size for data")
    
    indexCipher=privKey.size_in_bytes()
    indexSignature=len(cipher)-pubKey.size_in_bytes()
    
    signature=cipher[indexSignature:]
    seq=cipher[:indexCipher]
    cipher=cipher[indexCipher:indexSignature]

    pkcs1_oaep_ctx=PKCS1_OAEP.new(privKey)
    aes_info=pkcs1_oaep_ctx.decrypt(seq)

    if len(aes_info)<AES.key_size[2]+AES.block_size:
        raise ValueError("Invalid key size")
    
    kc=aes_info[:AES.key_size[2]]
    iv=aes_info[AES.key_size[2]:AES.key_size[2]+AES.block_size]

    sha256_ctx=SHA256.new()
    sha256_ctx.update(seq)
    sha256_ctx.update(iv)
    sha256_ctx.update(cipher)

    pss.new(pubKey).verify(sha256_ctx,signature)
                    
    return aes_decrypt_message(cipher,kc,iv)
    

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
        result=decrypt_message(data,pubKey,privKey)
        open(sys.argv[4],"wb").write(result)
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        print_help()
        sys.exit(-1)