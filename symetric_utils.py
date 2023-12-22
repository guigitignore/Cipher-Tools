#!python3

from Crypto.Hash import SHA256,HMAC
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
from struct import pack

SALT_LENGTH=8

# cipher message using aes
def aes_encrypt_message(msg:bytes,kc:bytes,iv:bytes)->bytes:
    aes_ctx=AES.new(kc,AES.MODE_CBC,iv=iv)
    padded_msg=pad(msg,AES.block_size)
    return aes_ctx.encrypt(padded_msg)

#decrypt message using aes
def aes_decrypt_message(cipher:bytes,kc:bytes,iv:bytes)->bytes:
    aes_ctx=AES.new(kc,AES.MODE_CBC,iv=iv)
    padded_msg=aes_ctx.decrypt(cipher)
    return unpad(padded_msg,AES.block_size)

# take a byte password, derive the key and return master key kc
def deriv_passwd(password:bytes,salt:bytes,counter:int=8192)->bytes:
    sha256_ctx=SHA256.new()

    sha256_ctx.update(password)
    sha256_ctx.update(salt)
    sha256_ctx.update(pack('<I',0))
    digest=sha256_ctx.digest()

    for i in range(1,counter):
        sha256_ctx=SHA256.new()
        sha256_ctx.update(digest)
        sha256_ctx.update(password)
        sha256_ctx.update(salt) 
        digest=sha256_ctx.digest()

    return digest

# derive master key into cipher key and integrity key
def deriv_master_key(master_key:bytes)->tuple[bytes,bytes]:
    sha256_ctx=SHA256.new()
    sha256_ctx.update(master_key)
    # add 0 for cipher key 
    sha256_ctx.update(pack('<I',0))

    kc=sha256_ctx.digest()

    sha256_ctx=SHA256.new()
    sha256_ctx.update(master_key)
    # add 1 for integrity key
    sha256_ctx.update(pack('<I',1))

    ki=sha256_ctx.digest()

    return kc,ki

# computes hmax of ciphered text
def hmac_secret(ki:bytes,cipher:bytes,salt:bytes,iv:bytes)->bytes:
    hmac_ctx=HMAC.new(ki,digestmod=SHA256)

    hmac_ctx.update(salt)
    hmac_ctx.update(iv)
    hmac_ctx.update(cipher)

    return hmac_ctx.digest()

