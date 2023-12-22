# Cipher Tools Project

This project allows you to encrypt and decrypt files using symetric and asymetric cipher algorithms.

## Setup

Create a virtual env and install dependencies

```
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```

## Utilities

### Symetric cipher algorithms

```
./protect_symetric.py <password> <input file> <output file>
./unprotect_symetric.py <password> <input file> <output file>
```

### Asymetric cipher algorithms

```
./protect_asymetric.py <pubkey file> <privkey file> <input file> <output file>
./unprotect_asymetric.py <pubkey file> <privkey file> <input file> <output file>
```

### Multi protect

This program allows you to send to several user a file using their public RSA keys. The file is signed using private key of the sender.

File format:

```
0x00 || SHA256(kpub-1) || RSA_kpub-1(Kc || IV) || ... || 0x00 || SHA256(kpub-N) || RSA_kpub-N(Kc || IV) || 0x01 || C || Sign
```

Usage:

```
./multi_protect.py -e  <input_file> <output_file> <my_sign_priv.pem> <my_ciph_pub.pem> [user1_ciph_pub.pem ... [userN_ciph_pub.pem]]
./multi_protect.py -d  <input_file> <output_file> <my_priv_ciph.pem> <my_pub_ciph.pem> <sender_sign_pub.pem> 
```
