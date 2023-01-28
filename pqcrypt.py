# PQcrypt
# Copyright (c) 2018 - 2022 Open Quantum Safe
# Copyright (c) 2022 ANISH M < aneesh25861@gmail.com >

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import datetime
import platform
import sys
import os
import sqlite3
import hashlib
import getpass
import argon2
import oqs
import lzma
import binascii
from time import sleep
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    
# Supported Post quantum Asymmetric key Ciphers.
supported_algos_encrypt = ('Kyber1024','Classic-McEliece-6688128','Classic-McEliece-6688128f','Classic-McEliece-6960119','Classic-McEliece-6960119f','Classic-McEliece-8192128','Classic-McEliece-8192128f','HQC-256')

# Supported Post quantum Digital Signature Algorithms.
supported_algos_sig = ('Dilithium5','Falcon-1024','SPHINCS+-Haraka-256f-robust','SPHINCS+-Haraka-256f-simple','SPHINCS+-Haraka-256s-robust','SPHINCS+-Haraka-256s-simple','SPHINCS+-SHA256-256f-robust','SPHINCS+-SHA256-256f-simple','SPHINCS+-SHA256-256s-robust','SPHINCS+-SHA256-256s-simple','SPHINCS+-SHAKE256-256f-robust','SPHINCS+-SHAKE256-256f-simple','SPHINCS+-SHAKE256-256s-robust','SPHINCS+-SHAKE256-256s-simple')

def start():
    print('\n<--- Task Started --->\n')

def fail():
    print('\n<--- Task Failed --->\n')
    sleep(5)
    sys.exit(1)

def complete():
    print('\n<--- Task Completed --->\n')

def check(file):
    if os.path.exists(file):
        os.remove(file)

# Convert binary data to ascii representation.
def binary2ascii(file,msg,iext,fext):
    if file.endswith(iext) is False:
        print('Invalid File Extension!')
        fail()
        return
    
    filename = file.split('.')[0]

    try:
        with open(file,'rb') as f:
            with open(filename+'.mod','wb') as w:
                buff = f.read()
                out = lzma.compress(buff)
                w.write(binascii.b2a_base64(out))
                
    except Exception as e:
        print(e)
        fail()
        return
    
    with open(filename+fext,'w') as k:
        k.write('\n--- PQP '+msg+' ---\n')
        with open(filename+'.mod') as m:
            buff=m.read()
            k.write(buff)
            k.write('--- PQP '+msg+' ---')

    os.remove(filename+'.mod')

# Convert Ascii Representation of data to Binary Data.
def ascii2binary(file,msg,iext,fext):
    if file.endswith(iext) is False:
        print('Invalid File Extension!')
        fail()
        return
    
    filename = file.split('.')[0]
    count = 0
    try:
        f = open(filename+'.mod','w')
        with open(file) as k:
            buff = k.readline()

            while len(buff) > 0 :
                buff = k.readline()
                if msg in buff:
                    count += 1
                    if count == 2:
                        f.close()
                        break
                    continue
                if count == 1:
                    f.write(buff)
    except Exception as e:
        print(e)
        fail()
        return

    with open(filename+fext,'wb') as w:
        with open(filename+'.mod','rb') as f:
                try:
                    buff = binascii.a2b_base64(f.read())
                    w.write(lzma.decompress(buff))
                except Exception as e:
                    print(e)
                    fail()

                
    os.remove(filename+'.mod')

def ascii2binary_publickey(key):
    if key.endswith('.cspub'):
        ascii2binary(key,'Public Key','.cspub','.spub')
        return '.spub'
    if key.endswith('.cpub'):
        ascii2binary(key,'Public Key','.cpub','.pub')
        return '.pub'

def binary2ascii_publickey(key):
    if key.endswith('.spub'):
        binary2ascii(key,'Public Key','.spub','.cspub')
    elif key.endswith('.pub'):
        binary2ascii(key,'Public Key','.pub','.cpub')

def fingerprint():

    start()
    file = input(' Enter public key:')
    if os.path.exists(file) is False:
        print('Public Key not found!')
        fail()
        return

    if file.split('.')[1] in ('cspub','cpub'):
        file = file.split('.')[0]+ ascii2binary_publickey(file)
        
    try:
        connect = sqlite3.connect(file)
        cursor = connect.cursor()
        content = cursor.execute('select key from map').fetchall()
        x = hashlib.sha512(content[0][0]).hexdigest()
        print('\n --- Fingerprint --- \n')
        print(' ',x[:len(x)//2],'\n ',x[len(x)//2:])
        connect.commit()
        cursor.close()
        connect.close()
        complete()
        
    except Exception as e:
        print(e)
        fail()
        return

def update():
    start()
    os.system('pip3 install cryptography -U')
    os.system('pip3 install argon2-cffi -U')
    complete()

def encrypt_decrypt():
    kems = oqs.get_enabled_KEM_mechanisms()

    # Generate New key Pair
    def genkeypair(kemalg):

        start()

        if kemalg not in supported_algos_encrypt :
            print('Algorthim not supported!')
            fail()
            return 

        with oqs.KeyEncapsulation(kemalg) as client:
            public_key = client.generate_keypair()
            connect = sqlite3.connect(hashlib.md5(public_key).hexdigest()+".pub")
            cursor = connect.cursor()
            cursor.execute('''create table map ( 
                        algo  varchar(25) not null,
                        key BLOB 
                        )''')
            cursor.execute('insert into map values (?,?)',(kemalg,public_key))
            connect.commit()
            cursor.close()
            connect.close()

            secret_key = client.export_secret_key()
            password = getpass.getpass('Enter Password to protect secret key:')
            password = bytes(password,'utf-8')
            salt = os.urandom(16)
            iv = os.urandom(12)
            key = argon2.low_level.hash_secret_raw(password, salt, 12, 2097152, 4, 32, argon2.low_level.Type.ID, 19)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(iv, secret_key, salt + bytes(kemalg,'utf-8'))

            connect = sqlite3.connect(hashlib.md5(public_key).hexdigest()+".sec")
            cursor = connect.cursor()
            cursor.execute('''create table map ( 
                        algo varchar(25),
                        iv   BLOB ,
                        salt BLOB ,
                        publickey BLOB ,
                        key BLOB not null 
                        )''')
            cursor.execute('insert into map values (?,?,?,?,?)',(kemalg,iv,salt,public_key,ciphertext))
            connect.commit()
            cursor.close()
            connect.close()

            choice = input('Do you need ASCII armoured public key?(Y/N):')
            if choice.lower() == 'y':
                binary2ascii_publickey(hashlib.md5(public_key).hexdigest()+'.pub')
                os.remove(hashlib.md5(public_key).hexdigest()+'.pub')
            complete()

    # Encryption Function
    def encrypt():

        start()
        public_key = ''
        publickey = input('Enter Public key:')
        if os.path.exists(publickey) is False:
            print('Public Key Not Found!')
            fail()
            return

        if publickey.split('.')[1] == 'cpub':
            publickey = publickey.split('.')[0]+ ascii2binary_publickey(publickey)
        file = input('\nEnter file:')
        if os.path.exists(file) is False:
            print('File not found!')
            fail()
            return

        try:
                connect = sqlite3.connect(publickey)
                cursor = connect.cursor()
                content = cursor.execute('select * from map').fetchall()
                if len(content) != 1:
                   print('Public Key File Corrupted!')
                   fail()
                   return
                cursor.close()
                connect.close()
                public_key = content[0][1]
                kemalg = content[0][0]
                if kemalg not in supported_algos_encrypt:
                    print('Algorithm not supported!')
                    fail()
                    return
                with oqs.KeyEncapsulation(kemalg) as server:
                    ciphertext, shared_secret_server = server.encap_secret(public_key)

                    # Create session key.    
                    hkey = shared_secret_server
                    hkdf = HKDF(
                                    algorithm=hashes.SHA512(),
                                    length=32,
                                    salt=b'\xba\xc7\\\x9cQV\xd8\xce\xc7\xae\xc6i\xde\xdf`&\xf4|\x1dc\xc9\xf5\xf7/\x0f>\x9e\xeb5\x98\xb4\xfb',
                                    info=b'\xa3x\xeb\x95\x03\xd1\xccv\xab\x15I\xd0\xd6\x0f\x8f,\n\xcb\x89\xb8\x17 1cjeQ\x0b\xd7\x93\x15\xad',
                                )

                    key = hkdf.derive(hkey)
                    iv = os.urandom(12)
                    aesgcm = AESGCM(key)

                    try:
                        f = open(file,'rb')
                        buffer = f.read()
                        ctxt = aesgcm.encrypt(iv, buffer, ciphertext)
                        check(file+'.cry')
                        connect = sqlite3.connect(file+".cry")
                        cursor = connect.cursor()
                        cursor.execute('''create table map ( 
                                          iv   BLOB ,
                                          ctxt BLOB not null ,
                                          ciphertext BLOB
                                       )''')
                        cursor.execute('insert into map values (?,?,?)',(iv,ctxt,ciphertext))
                        connect.commit()
                        cursor.close()
                        connect.close()
                        complete()

                    except Exception as e:
                        print(e)
                        fail()
                        return
            
                choice = input('Do you need ASCII armoured Encrypted Message ?(Y/N):')
                if choice.lower() == 'y':
                    binary2ascii(file+'.cry','Encrypted Message','.cry','.ccry')
                    os.remove(file+'.cry')
           
        except Exception as e:
            print(e)
            fail()
            return
    
    # Decryption Function
    def decrypt():
        
        start()
        secret_key = ''
        secretkey = input('Enter Private key:')
        if os.path.exists(secretkey) is False:
            print('Private Key not Found!')
            fail()
            return

        file = input('\nEnter Encrypted file:')
        if os.path.exists(file) is False:
            print('File Not Found')
            fail()
            return
        
        if file.endswith('.ccry'):
            ascii2binary(file,'Encrypted Message','.ccry','.cry')
            os.remove(file)
            file = file.replace('.ccry','.cry')

        try:
            connect = sqlite3.connect(secretkey)
            cursor = connect.cursor()
            content = cursor.execute('select * from map').fetchall()
            if len(content) != 1:
                print('File Corrupted!')
                fail()
                return
            cursor.close()
            connect.close()
            kemalg = content[0][0]
            iv = content[0][1]
            salt = content[0][2]
            ctxt1 = content[0][4]
            password = getpass.getpass('Enter Password to unlock secret key:')
            password = bytes(password,'utf-8')
            key = argon2.low_level.hash_secret_raw(password, salt, 12, 2097152, 4, 32, argon2.low_level.Type.ID, 19)
            aesgcm = AESGCM(key)

            try:
                secret_key = aesgcm.decrypt(iv, ctxt1, salt + bytes(kemalg,'utf-8'))
            except Exception as e:
                print('Incorrect Password or Private key File corrupted!')
                fail()
                return

            # Restore Session.
            client = oqs.KeyEncapsulation(kemalg, secret_key)
            
            # unlock payload
            connect = sqlite3.connect(file)
            cursor = connect.cursor()
            content = cursor.execute('select * from map').fetchall()
            if len(content) != 1:
                print('File Corrupted!')
                fail()
                return
            cursor.close()
            connect.close()
            iv = content[0][0]
            ctxt = content[0][1]
            ciphertext = content[0][2]
            shared_secret_client = client.decap_secret(ciphertext)
            hkdf = HKDF(
                        algorithm=hashes.SHA512(),
                        length=32,
                        salt=b'\xba\xc7\\\x9cQV\xd8\xce\xc7\xae\xc6i\xde\xdf`&\xf4|\x1dc\xc9\xf5\xf7/\x0f>\x9e\xeb5\x98\xb4\xfb',
                        info=b'\xa3x\xeb\x95\x03\xd1\xccv\xab\x15I\xd0\xd6\x0f\x8f,\n\xcb\x89\xb8\x17 1cjeQ\x0b\xd7\x93\x15\xad',
                        )
            key = hkdf.derive(shared_secret_client)
            aesgcm = AESGCM(key)

            try:
                dump = aesgcm.decrypt(iv, ctxt, ciphertext)
            except Exception as e:
                print('Message Integrity Check Failed: Someone has modified contents of message or you choosed Invalid private key?')
                fail()
                return

            ofile = input('Enter Name of output file:')
            with open( ofile,'wb') as b:
                b.write(dump)
            complete()

        except Exception as e:
            print(e)
            fail()
            return

    def menu():
        print('\n --- Encryption/Decryption Mode ---\n')
        print(' 1) Generate key pair')
        print(' 2) Encrypt data')
        print(' 3) Decrypt Data')
        
        while True:
            choice = input('\nEnter choice:')

            if choice == '1':
                print('\n--- Supported Ciphers ---\n')
                print(' 1) Kyber1024 [ Recommended ]')
                print(' 2) HQC-256')
                print(' 3) Classic-McEliece-6688128')
                print(' 4) Classic-McEliece-6688128f')
                print(' 5) Classic-McEliece-6960119')
                print(' 6) Classic-McEliece-6960119f')
                print(' 7) Classic-McEliece-8192128')
                print(' 8) Classic-McEliece-8192128f')

                ch = input('\nEnter choice:')
                if ch == '1':
                    genkeypair('Kyber1024')
                    break
                elif ch == '2':
                    genkeypair('HQC-256')
                    break
                elif ch == '3':
                    genkeypair('Classic-McEliece-6688128')
                    break
                elif ch == '4':
                    genkeypair('Classic-McEliece-6688128f')
                    break
                elif ch == '5':
                    genkeypair('Classic-McEliece-6960119')
                    break
                elif ch == '6':
                    genkeypair('Classic-McEliece-6960119f')
                    break
                elif ch == '7':
                    genkeypair('Classic-McEliece-8192128')
                    break
                else:
                    genkeypair('Classic-McEliece-8192128f')
                    break
                
            elif choice == '2':
                encrypt()
                break

            elif choice == '3':
                decrypt()
                break

            elif choice in ('c','close','exit') :
                sys.exit(0)

    menu()

# Function to extract public key material from private key.
def extract_public_key():
        start()
        count = 0
        secretkey = input('Enter Private key:')
        if os.path.exists(secretkey) is False:
            print('File Not Found!')
            fail()
            return

        try:
            connect = sqlite3.connect(secretkey)
            cursor = connect.cursor()
            content = cursor.execute('select * from map').fetchall()
            if len(content) != 1:
                print('File Corrupted!')
                fail()
                return
            cursor.close()
            connect.close()
            kemalg = content[0][0]
            public_key = content[0][3]
            
            if secretkey.endswith('.sec'):
                check(hashlib.md5(public_key).hexdigest()+".pub")
                connect = sqlite3.connect(hashlib.md5(public_key).hexdigest()+".pub")
                count = 1
            elif secretkey.endswith('.ssec'):
                check(hashlib.md5(public_key).hexdigest()+".spub")
                connect = sqlite3.connect(hashlib.md5(public_key).hexdigest()+".spub")
                count = 2
            cursor = connect.cursor()
            cursor.execute('''create table map ( 
                        algo  varchar(25) not null,
                        key BLOB 
                        )''')
            cursor.execute('insert into map values (?,?)',(kemalg,public_key))
            connect.commit()
            cursor.close()
            connect.close()
        except Exception as e:
            print(e)
            fail()
            return

        choice = input('Do you need ASCII armoured public key?(Y/N):')
        if choice.lower() == 'y':
            if count == 1:
                binary2ascii_publickey(hashlib.md5(public_key).hexdigest()+'.pub')
                os.remove(hashlib.md5(public_key).hexdigest()+'.pub')
            elif count == 2:
                binary2ascii_publickey(hashlib.md5(public_key).hexdigest()+'.spub')
                os.remove(hashlib.md5(public_key).hexdigest()+'.spub')
        complete()
        

def sign_verify():
    sigs = oqs.get_enabled_sig_mechanisms()

    # Generate New key Pair
    def genkeypair(sigalg):

        start()

        if sigalg not in supported_algos_sig:
            print('Algorithm not supported!')
            fail()
            return
            
        with oqs.Signature(sigalg) as client:
            public_key = client.generate_keypair()
            connect = sqlite3.connect(hashlib.md5(public_key).hexdigest()+".spub")
            cursor = connect.cursor()
            cursor.execute('''create table map ( 
                        algo  varchar(25) not null,
                        key BLOB 
                        )''')
            cursor.execute('insert into map values (?,?)',(sigalg,public_key))
            connect.commit()
            cursor.close()
            connect.close()

            secret_key = client.export_secret_key()
            password = getpass.getpass('Enter Password to protect secret key:')
            password = bytes(password,'utf-8')
            salt = os.urandom(16)
            iv = os.urandom(12)
            key = argon2.low_level.hash_secret_raw(password, salt, 12, 2097152, 4, 32, argon2.low_level.Type.ID, 19)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(iv, secret_key, salt + bytes(sigalg,'utf-8'))

            connect = sqlite3.connect(hashlib.md5(public_key).hexdigest()+".ssec")
            cursor = connect.cursor()
            cursor.execute('''create table map ( 
                        algo varchar(25),
                        iv   BLOB ,
                        salt BLOB ,
                        publickey BLOB ,
                        key BLOB not null 
                        )''')
            cursor.execute('insert into map values (?,?,?,?,?)',(sigalg,iv,salt,public_key,ciphertext))
            connect.commit()
            cursor.close()
            connect.close()
            
            choice = input('Do you need ASCII armoured public key?(Y/N):')
            if choice.lower() == 'y':
                binary2ascii_publickey(hashlib.md5(public_key).hexdigest()+'.spub')
                os.remove(hashlib.md5(public_key).hexdigest()+'.spub')
            complete()

    # Function to Verify Digital Signature
    def verify():
        start()
        public_key = ''
        publickey = input('Enter Public key:')
        if os.path.exists(publickey) is False:
            print('Public Key not found!')
            fail()
            return

        if publickey.split('.')[1] == 'cspub':
            publickey = publickey.split('.')[0]+ ascii2binary_publickey(publickey)
        file = input('\nEnter file which has to be verified:')
        if os.path.exists(file) is False:
            print('File Not Found!')
            fail()
            return
            
        sigfile = input('\nEnter Digital Signature File Location:')
        if os.path.exists(sigfile) is False:
            print('File Not Found!')
            fail()
            return

        if sigfile.endswith('.csig'):
            ascii2binary(sigfile,'Digital Signature','.csig','.qsig')
            os.remove(sigfile)
            sigfile = sigfile.replace('.csig','.qsig')
            
        limit = 1024
        v = hashlib.sha512()
        with open(file,'rb+') as f:
                buff = f.read(limit)
                v.update(buff)
                while len(buff)>0:
                    buff = f.read(limit)
                    v.update(buff)
        hash_initial = str(v.hexdigest())

        try:
                connect = sqlite3.connect(publickey)
                cursor = connect.cursor()
                content = cursor.execute('select * from map').fetchall()
                cursor.close()
                connect.close()
                if len(content) != 1:
                   print('File Corrupted!')
                   fail()
                   return

                public_key = content[0][1]
                sigalg = content[0][0]
                verifier = oqs.Signature(sigalg)
                if sigalg not in supported_algos_sig:
                    print('Algorithm not supported!')
                    fail()
                    return

                with oqs.Signature(sigalg) as server:

                    try:
                        connect = sqlite3.connect(sigfile)
                        cursor = connect.cursor()
                        content = cursor.execute('select * from map').fetchall() 
                        hash = content[0][0]
                        sig = content[0][1]
                        if hash_initial == hash.split('%')[1]:
                            is_valid = verifier.verify(bytes(hash,'utf-8'), sig, public_key)
                            if is_valid == True:
                                print('Good Signature , Data signed on',hash.split('%')[2])
                                print('\nDigital Signature made using key with fingerprint:-\n')
                                x = hash.split('%')[0]
                                print(' ',x[:len(x)//2],'\n ',x[len(x)//2:])
                            else:
                                print('Bad Signature!')
                                print('\nDigital Signature made using key with fingerprint:-\n')
                                x = hash.split('%')[0]
                                print(' ',x[:len(x)//2],'\n ',x[len(x)//2:])

                        cursor.close()
                        connect.close()
                        complete()
                    except Exception as e:
                        print(e)
                        fail()
                        return

        except Exception as e :
            print(e)
            fail()
            return
    
    # Function to create Digital Signature.
    def sign():
        start()
        secret_key = ''
        secretkey = input('Enter Private key:')
        if os.path.exists(secretkey) is False:
            print('Private Key not Found!')
            fail()
            return

        file = input('\nEnter file which will be signed:')
        if os.path.exists(file) == False:
            print('File Not Found')
            fail()
            return

        try:
            connect = sqlite3.connect(secretkey)
            cursor = connect.cursor()
            content = cursor.execute('select * from map').fetchall()
            cursor.close()
            connect.close()
            if len(content) != 1:
                print('File Corrupted!')
                fail()
                return

            sigalg = content[0][0]
            iv = content[0][1]
            salt = content[0][2]
            public_key = content[0][3]
            ctxt1 = content[0][4]
            password = getpass.getpass('Enter Password to unlock secret key:')
            password = bytes(password,'utf-8')
            key = argon2.low_level.hash_secret_raw(password, salt, 12, 2097152, 4, 32, argon2.low_level.Type.ID, 19)
            aesgcm = AESGCM(key)

            try:
                secret_key = aesgcm.decrypt(iv, ctxt1, salt + bytes(sigalg,'utf-8'))
            except Exception as e:
                print('Incorrect Password or Private key File Corrupted!')
                fail()
                return 

            # Restore Session.
            client = oqs.Signature(sigalg, secret_key)
            
            # create Signature.
            limit = 1024
            v = hashlib.sha512()
            with open(file,'rb+') as f:
                buff = f.read(limit)
                v.update(buff)
                while len(buff)>0:
                    buff = f.read(limit)
                    v.update(buff)
            d = str(hashlib.sha512(public_key).hexdigest()) + '%'
            d += str(v.hexdigest()) + '%'
            d += str(datetime.datetime.today())
            sign1 = client.sign(d.encode())
            check(file+'.qsig')
            connect = sqlite3.connect(file+'.qsig')
            cursor = connect.cursor()
            cursor.execute('''create table map ( 
                                          hash   varchar(100) ,
                                          sig BLOB not null 
                                       )''')
            cursor.execute('insert into map values (?,?)',(d,sign1))
            connect.commit()
            cursor.close()
            connect.close()
            
            choice = input('Do you need ascii armoured digital signature?(Y/n):')
            if choice.lower() == 'y':
                binary2ascii(file+'.qsig','Digital Signature','.qsig','.csig')
                os.remove(file+'.qsig')
            complete()

        except Exception as e :
            print(e)
            fail()
            return

    def menu():
        print('\n --- Sign/Verify Data ---\n')
        print(' 1) Generate key pair')
        print(' 2) Digitally Sign Data')
        print(' 3) Verify Digital Signature')
        
        while True:
            choice = input('\nEnter choice:')

            if choice == '1':
                print('\n--- Supported Algorithms ---\n')
                print(' 1) Dilithium5 [ Recommended ]')
                print(' 2) Falcon-1024')
                print(' 3) SPHINCS+-Haraka-256f-robust')
                print(' 4) SPHINCS+-Haraka-256f-simple')
                print(' 5) SPHINCS+-Haraka-256s-robust')
                print(' 6) SPHINCS+-Haraka-256s-simple')
                print(' 7) SPHINCS+-SHA256-256f-robust')
                print(' 8) SPHINCS+-SHA256-256f-simple')
                print(' 9) SPHINCS+-SHA256-256s-robust')
                print(' 10) SPHINCS+-SHA256-256s-simple')
                print(' 11) SPHINCS+-SHAKE256-256f-robust')
                print(' 12) SPHINCS+-SHAKE256-256f-simple')
                print(' 13) SPHINCS+-SHAKE256-256s-robust')
                print(' 14) SPHINCS+-SHAKE256-256s-simple')

                ch = input('\nEnter choice:')
                if ch == '1':
                    genkeypair('Dilithium5')
                    break
                elif ch == '2':
                    genkeypair('Falcon-1024')
                    break
                elif ch == '3':
                    genkeypair('SPHINCS+-Haraka-256f-robust')
                    break
                elif ch == '4':
                    genkeypair('SPHINCS+-Haraka-256f-simple')
                    break
                elif ch == '5':
                    genkeypair('SPHINCS+-Haraka-256s-robust')
                    break
                elif ch == '6':
                    genkeypair('SPHINCS+-Haraka-256s-simple')
                    break
                elif ch == '7':
                    genkeypair('SPHINCS+-SHA256-256f-robust')
                    break
                elif ch == '8':
                    genkeypair('SPHINCS+-SHA256-256f-simple')
                    break
                elif ch == '9':
                    genkeypair('SPHINCS+-SHA256-256s-robust')
                    break
                elif ch == '10':
                    genkeypair('SPHINCS+-SHA256-256s-simple')
                    break
                elif ch == '11':
                    genkeypair('SPHINCS+-SHAKE256-256f-robust')
                    break
                elif ch == '12':
                    genkeypair('SPHINCS+-SHAKE256-256f-simple')
                    break
                elif ch == '13':
                    genkeypair('SPHINCS+-SHAKE256-256s-robust')
                    break
                else: 
                    genkeypair('SPHINCS+-SHAKE256-256s-simple')
                    break

            elif choice == '2':
                sign()
                break
            elif choice == '3':
                verify()
                break
            elif choice in ('c','close','exit') :
                sys.exit(0)
            
    menu()

def about():
    
    print('''
    
PQcrypt is an open source project developed by 
Anish M <aneesh25861@gmail.com> with the mission of 
making Post Quantum cryptography usable for common man .

Huge Thanks to Open Quantum Safe Project ,
Developers of argon2-cffi and Python 
Cryptography Library . If you find this project 
useful consider donating to these projects.

For Feature Requests and for reporting Bugs contact
me on https://github.com/anish-m-code 
    
          ''')
    sleep(5)

def main_menu():

    print('\n --- PQcrypt : Post Quantum Cryptography Toolkit --- \n')
    print('\n Menu:-\n')
    print(' 1) Encrypt/Decrypt Data')
    print(' 2) Digitally Sign/Verify Data')
    print(' 3) Check Fingerprint of Public key')
    print(' 4) Export/Extract Public key from Private key')
    print(' 5) Update Dependencies')
    print(' 6) About')
    ch = input('\nEnter choice:')
    if ch == '1':
        encrypt_decrypt()
    elif ch == '2':
        sign_verify()
    elif ch == '3':
        fingerprint()
    elif ch == '4':
        extract_public_key()
    elif ch == '5':
        update()
    elif ch == '6':
        about()
    elif ch in ('exit','c','close'):
        sys.exit(0)
    else:
        return

while True:
    try:
        main_menu()
    except KeyboardInterrupt:
        print('Good bye! Exiting ...')
        sys.exit(0)
    except Exception as e:
        print(e)
        sys.exit(1)