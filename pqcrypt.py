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
from time import sleep
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    
# Supported Post quantum Asymmetric key Ciphers.
supported_algos_encrypt = ('Kyber1024','FireSaber-KEM','NTRU-HPS-4096-1229','NTRU-HRSS-1373','Classic-McEliece-6688128','Classic-McEliece-6688128f','Classic-McEliece-6960119','Classic-McEliece-6960119f','Classic-McEliece-8192128','Classic-McEliece-8192128f')

# Supported Post quantum Digital Signature Algorithms.
supported_algos_sig = ('Dilithium5','Dilithium5-AES','Falcon-1024','Rainbow-V-Classic','Rainbow-V-Circumzenithal','Rainbow-V-Compressed')

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

def fingerprint():

    start()
    file = input(' Enter public key:')
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
            iv = os.urandom(16)
            key = argon2.low_level.hash_secret_raw(password, salt, 12, 2097152, 4, 32, argon2.low_level.Type.ID, 19)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(secret_key) + encryptor.finalize()

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
            complete()

    # Encryption Function
    def encrypt():

        start()
        public_key = ''
        publickey = input('Enter Public key:')
        file = input('\nEnter file:')

        try:
                connect = sqlite3.connect(publickey)
                cursor = connect.cursor()
                content = cursor.execute('select * from map').fetchall()
                if len(content) != 1:
                   print('File Corrupted!')
                   return
                cursor.close()
                connect.close()
                public_key = content[0][1]
                kemalg = content[0][0]
                if kemalg not in supported_algos_encrypt:
                    print('Algorithm not supported!')
                    return
                with oqs.KeyEncapsulation(kemalg) as server:
                    ciphertext, shared_secret_server = server.encap_secret(public_key)

                    # Create session key.    
                    key = shared_secret_server
                    iv = os.urandom(16)
                    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
                    encryptor = cipher.encryptor()

                    try:
                        f = open(file,'rb')
                        buffer = f.read()
                        ctxt = encryptor.update(buffer) + encryptor.finalize()
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

        except Exception as e:
            print(e)
            fail()
            return
    
    # Decryption Function
    def decrypt():
        
        start()
        secret_key = ''
        secretkey = input('Enter Private key:')
        file = input('\nEnter Encrypted file:')
        if os.path.exists(file) == False:
            print('File Not Found')
            return

        try:
            connect = sqlite3.connect(secretkey)
            cursor = connect.cursor()
            content = cursor.execute('select * from map').fetchall()
            if len(content) != 1:
                print('File Corrupted!')
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
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
            decryptor = cipher.decryptor()
            secret_key = decryptor.update(ctxt1) + decryptor.finalize()

            # Restore Session.
            client = oqs.KeyEncapsulation(kemalg, secret_key)
            
            # unlock payload
            connect = sqlite3.connect(file)
            cursor = connect.cursor()
            content = cursor.execute('select * from map').fetchall()
            if len(content) != 1:
                print('File Corrupted!')
                return
            cursor.close()
            connect.close()
            iv = content[0][0]
            ctxt = content[0][1]
            ciphertext = content[0][2]
            shared_secret_client = client.decap_secret(ciphertext)
            cipher = Cipher(algorithms.AES(shared_secret_client), modes.CFB(iv))
            decryptor = cipher.decryptor()
            dump = decryptor.update(ctxt) + decryptor.finalize()
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
                print(' 1) Kyber1024')
                print(' 2) FireSaber')
                print(' 3) NTRU-HPS-4096-1229')
                print(' 4) NTRU-HRSS-1373')
                print(' 5) Classic-McEliece-6688128')
                print(' 6) Classic-McEliece-6688128f')
                print(' 7) Classic-McEliece-6960119')
                print(' 8) Classic-McEliece-6960119f')
                print(' 9) Classic-McEliece-8192128')
                print(' 10) Classic-McEliece-8192128f')

                ch = input('\nEnter choice:')
                if ch == '1':
                    genkeypair('Kyber1024')
                    break
                elif ch == '2':
                    genkeypair('FireSaber-KEM')
                    break
                elif ch == '3':
                    genkeypair('NTRU-HPS-4096-1229')
                    break
                elif ch == '4':
                    genkeypair('NTRU-HRSS-1373')
                    break
                elif ch == '5':
                    genkeypair('Classic-McEliece-6688128')
                    break
                elif ch == '6':
                    genkeypair('Classic-McEliece-6688128f')
                    break
                elif ch == '7':
                    genkeypair('Classic-McEliece-6960119')
                    break
                elif ch == '8':
                    genkeypair('Classic-McEliece-6960119f')
                    break
                elif ch == '9':
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
        secretkey = input('Enter Private key:')
        if os.path.exists(secretkey) == False:
            print('File Not Found')
            return

        try:
            connect = sqlite3.connect(secretkey)
            cursor = connect.cursor()
            content = cursor.execute('select * from map').fetchall()
            if len(content) != 1:
                print('File Corrupted!')
                return
            cursor.close()
            connect.close()
            kemalg = content[0][0]
            public_key = content[0][3]

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
        except Exception as e:
            print(e)
            fail()
            return
        complete()

def sign_verify():
    sigs = oqs.get_enabled_sig_mechanisms()

    # Generate New key Pair
    def genkeypair(sigalg):

        start()
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
            iv = os.urandom(16)
            key = argon2.low_level.hash_secret_raw(password, salt, 12, 2097152, 4, 32, argon2.low_level.Type.ID, 19)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(secret_key) + encryptor.finalize()

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
            complete()

    # Function to Verify Digital Signature
    def verify():
        start()
        public_key = ''
        publickey = input('Enter Public key:')
        file = input('\nEnter filename:')
        sigfile = input('\nEnter Digital Signature File Location:')
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

        except FileNotFoundError:
            print('Public Key File Not Found!')
            fail()
            return
    
    # Function to create Digital Signature.
    def sign():
        start()
        secret_key = ''
        secretkey = input('Enter Private key:')
        file = input('\nEnter file:')
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
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
            decryptor = cipher.decryptor()
            secret_key = decryptor.update(ctxt1) + decryptor.finalize()

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
            complete()

        except FileNotFoundError:
            print('File Not Found!')
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
                print(' 1) Dilithium5')
                print(' 2) Dilithium5-AES')
                print(' 3) Falcon-1024')
                print(' 4) Rainbow-V-Classic')
                print(' 5) Rainbow-V-Circumzenithal')
                print(' 6) Rainbow-V-Compressed')

                ch = input('\nEnter choice:')
                if ch == '1':
                    genkeypair('Dilithium5')
                    break
                elif ch == '2':
                    genkeypair('Dilithium5-AES')
                    break
                elif ch == '3':
                    genkeypair('Falcon-1024')
                    break
                elif ch == '4':
                    genkeypair('Rainbow-V-Classic')
                    break
                elif ch == '5':
                    genkeypair('Rainbow-V-Circumzenithal')
                    break
                else:
                    genkeypair('Rainbow-V-Compressed')
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
        main_menu()
    elif ch == '2':
        sign_verify()
        main_menu()
    elif ch == '3':
        fingerprint()
        main_menu()
    elif ch == '4':
        extract_public_key()
        main_menu()
    elif ch == '5':
        update()
        main_menu()
    elif ch == '6':
        about()
        main_menu()
    else:
        main_menu()
main_menu()