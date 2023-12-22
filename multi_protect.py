#!python3

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from typing import Callable
import sys
from symetric_utils import aes_encrypt_message,aes_decrypt_message

def print_help():
    print("Usage:")
    print("./multi_protect.py -e  <input_file> <output_file> <my_sign_priv.pem> <my_ciph_pub.pem> [user1_ciph_pub.pem ... [userN_ciph_pub.pem]]")
    print("./multi_protect.py -d  <input_file> <output_file> <my_priv_ciph.pem> <my_pub_ciph.pem> <sender_sign_pub.pem> ")


def encrypt(message:bytes,signPriv:bytes,ciphPub:bytes,*userPub:bytes)->bytes:
    pubKeys=[ciphPub,*userPub]
    kc=get_random_bytes(AES.key_size[2])
    iv=get_random_bytes(AES.block_size)

    out=bytes()
    for key in pubKeys:
        out+=b'\x00'

        #add sha256 of public key
        sha256_ctx=SHA256.new()
        sha256_ctx.update(key)
        out+=sha256_ctx.digest()

        #cipher kc and iv with each pub keys
        pkcs1_oaep_ctx=PKCS1_OAEP.new(RSA.import_key(key))
        out+=pkcs1_oaep_ctx.encrypt(kc+iv)

    out+=b'\x01'

    # add cipher message
    out+=aes_encrypt_message(message,kc,iv)

    #sign all message
    sha256_ctx=SHA256.new()
    sha256_ctx.update(out)
    pss_ctx=pss.new(RSA.import_key(signPriv))
    out+=pss_ctx.sign(sha256_ctx)

    return out


def decrypt(message:bytes,ciphPriv:bytes,ciphPub:bytes,senderPub:bytes)->bytes:
    senderPub:RSA.RsaKey=RSA.import_key(senderPub)
    ciphPriv:RSA.RsaKey=RSA.import_key(ciphPriv)

    if len(message)<SHA256.digest_size*2+senderPub.size_in_bytes()+2:
        raise ValueError("Invalid size for data")
    
    #extract signature
    signatureIndex=len(message)-senderPub.size_in_bytes()
    signature=message[signatureIndex:]

    #remove signature part
    message=message[:signatureIndex]

    #check signature
    sha256_ctx=SHA256.new()
    sha256_ctx.update(message)
    pss.new(senderPub).verify(sha256_ctx,signature)

    #compute pubKey digest
    sha256_ctx=SHA256.new()
    sha256_ctx.update(ciphPub)
    ciphPubDigest=sha256_ctx.digest()
    #print(ciphPub.export_key())

    keyIndex=0
    cipheredKeys=None

    while message[keyIndex]!=1:
        keyIndex+=1
        if cipheredKeys is None:
            keyDigest=message[keyIndex:keyIndex+SHA256.digest_size]
            keyIndex+=SHA256.digest_size
            if keyDigest==ciphPubDigest: 
                cipheredKeys=message[keyIndex:keyIndex+ciphPriv.size_in_bytes()]

            keyIndex+=ciphPriv.size_in_bytes()
        else:
            keyIndex+=SHA256.digest_size+ciphPriv.size_in_bytes()

        if keyIndex>=len(message):
            raise TypeError("File format in incorrect")

    if cipheredKeys is None:
        raise IndexError("Cannot find your public key in file")
    
    #decrypt aes keys using private key
    pkcs1_oaep_ctx=PKCS1_OAEP.new(ciphPriv)
    aes_info=pkcs1_oaep_ctx.decrypt(cipheredKeys)

    if len(aes_info)<AES.key_size[2]+AES.block_size:
        raise ValueError("Invalid key size")
    
    kc=aes_info[:AES.key_size[2]]
    iv=aes_info[AES.key_size[2]:AES.key_size[2]+AES.block_size]

    return aes_decrypt_message(message[keyIndex+1:],kc,iv)
    


def parse_args(args:list[str]):
    if len(args)<2:
        print_help()
        return 1
    
    fun:Callable
    
    match args[1]:
        case '-e':
            if len(args)<6:
                print("Missing arguments")
                print_help()
                return 1
            fun=encrypt

        case '-d':
            if len(args)<7:
                print("Missing arguments")
                print_help()
                return 1
            #print(open(args[5],"rb").read())
            fun=decrypt

        case _:
            print(f"Unrecognized mode {args[1]}")
            print_help()
            return 1
    
    try:
        rsaKeys:list[bytes]=[open(key,"rb").read() for key in args[4:]]
        inputBytes=open(args[2],"rb").read()
        outputBytes=fun(inputBytes,*rsaKeys)

        with open(args[3],"wb") as out:
            out.write(outputBytes)
        return 0

    except Exception as e:
        print(f"An error occurred during \"{fun.__name__}\" process: {str(e)}")
        print_help()
        return 1



if __name__=="__main__":
    ret=parse_args(sys.argv)
    sys.exit(ret)