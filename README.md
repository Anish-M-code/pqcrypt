
# PQcrypt : Post Quantum Cryptography toolkit

PQcrypt is a easy to use Post Quantum Cryptography tool for Linux Users.

<img src="https://github.com/Anish-M-code/pqcrypt/raw/main/pqcrypt.png">

System Requirements
--------------------

A modern PC with atleast 4GB RAM and CPU having x86_64 architecture or 64 bit support

running one of the following supported operating systems :-

* Debian/Debian Based Linux Distro 
* Ubuntu / Ubuntu Based Linux Distro
* Fedora Linux / Fedora based Linux Distro 
* Arch Linux / Arch Linux Based Distro

Quick Installation
------------------

To Install from this Github Repo For Debian/Ubuntu based linux Distributions:

Run the following commands in Linux terminal to install:-

```
git clone https://github.com/Anish-M-code/pqcrypt.git
```
Then simply type the following command to get started :- 

```
cd pqcrypt && sh install.sh
```
To run the program after installation simply type :-

```
sh run.sh
```
For other supported operating systems refer [ Instructions](/Install.md) here

Supported Algorithms : -
--------------------

Public-key Encryption and Key-establishment Algorithms:-

1) Kyber1024 [ Recommended ]

2) HQC-256

3) Classic-McEliece-6688128

4) Classic-McEliece-6688128f

5) Classic-McEliece-6960119

6) Classic-McEliece-6960119f

7) Classic-McEliece-8192128

8) Classic-McEliece-8192128f

Digital Signature Algorithms : -

1) Dilithium5 [ Recommended ]

2) Falcon-1024

3) SPHINCS+-Haraka-256f-robust

4) SPHINCS+-Haraka-256f-simple

5) SPHINCS+-Haraka-256s-robust

6) SPHINCS+-Haraka-256s-simple

7) SPHINCS+-SHA256-256f-robust

8) SPHINCS+-SHA256-256f-simple

9) SPHINCS+-SHA256-256s-robust

10) SPHINCS+-SHA256-256s-simple

11) SPHINCS+-SHAKE256-256f-robust

12) SPHINCS+-SHAKE256-256f-simple

13) SPHINCS+-SHAKE256-256s-robust

14) SPHINCS+-SHAKE256-256s-simple

Features : -
--------

1) Only NIST 3rd Round Public-key Encryption & Key-establishment Algorithms and Digital Signature Algorithms selected for standardization and Algorithms considered for fourth round of analysis are supported.

2) All Algorithms used in this project use parameter sets which claim NIST Level 5 which provide highest security.

2) Uses AES256-GCM and Argon2id Key Derviation to protect secret keys and for Hybrid Encryption of Data.

Contributing to PQcrypt
---------------------

Currently i consider this as a personal project , All public contributions are welcome. Feel free to open issues if something breaks . Note this project may remain without activity for long periods of time, unless it is marked archived it is active and accepts contributions.

Limitations and Security Support
---------------------------------

For Security support and reporting bugs refer [ SECURITY](/SECURITY.md).

#### PQcrypt eats data. Use it with caution. Author is not a Professional Cryptographer.

THE DEVELOPER WILL NOT BE RESPONSIBLE FOR ANY DAMAGES ARISING FROM THE USE OF THIS TOOL. 
THIS TOOL WAS DEVELOPED FOR EDUCATIONAL AND ETHICAL EXPERIMENTING PURPOSE ONLY .

References
----------

* https://soatok.blog/2021/11/17/understanding-hkdf/
* https://github.com/open-quantum-safe/liboqs/discussions/1262
* https://crypto.stackexchange.com/questions/101066/is-argon2-quantum-safe
* https://crypto.stackexchange.com/questions/103918/in-a-pgp-like-application-would-compress-and-encrypt-leak-information
* https://crypto.stackexchange.com/questions/101159/can-32-byte-shared-secret-can-be-given-as-input-to-hkdf-sha512
* https://crypto.stackexchange.com/questions/101163/minimum-length-of-salt-and-info-for-hkdf
* https://crypto.stackexchange.com/questions/101651/for-post-quantum-security-is-any-hmac-with-256-bit-key-secure
* https://crypto.stackexchange.com/questions/101612/common-pitfalls-to-be-taken-care-of-while-implementing-encrypt-then-hmac-scheme
* https://crypto.stackexchange.com/questions/101164/can-encrypt-then-mac-using-hmac-sha256-with-aes-256-gcm-protect-against-attacks
* https://crypto.stackexchange.com/questions/101173/if-attacker-modifies-salt-used-for-hkdf-used-for-splitting-keys-for-encryption-a
* https://crypto.stackexchange.com/questions/101118/can-raw-hash-be-used-as-secret-key
* https://crypto.stackexchange.com/questions/101149/could-you-reuse-the-iv-for-aes256-gcm-as-salt-for-hkdf-sha256
* https://crypto.stackexchange.com/questions/101181/to-derive-multiple-keys-from-single-shared-secret-can-i-safely-ignore-info-and-s



