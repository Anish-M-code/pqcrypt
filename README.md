
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

1) Kyber1024

2) FireSaber

3) NTRU-HPS-4096-1229

4) NTRU-HRSS-1373

5) Classic-McEliece-6688128

6) Classic-McEliece-6688128f

7) Classic-McEliece-6960119

8) Classic-McEliece-6960119f

9) Classic-McEliece-8192128

10) Classic-McEliece-8192128f

Digital Signature Algorithms : -

1) Dilithium5

2) Dilithium5-AES

3) Falcon-1024

Features : -
--------

1) Only NIST 3rd Round Finalists Public-key Encryption & Key-establishment Algorithms and Digital Signature Algorithms are supported.

2) All Algorithms used in this project use parameter sets which claim NIST Level 5 which provide highest security.

2) Uses AES256 and Argon2id Key Derviation to protect secret keys and for Hybrid Encryption of Data.

Contributing to PQcrypt
---------------------

Currently i consider this as a personal project so i dont expect public contributions. Feel free to open issues if something breaks .

Limitations and Security Support
---------------------------------

For Security support and reporting bugs refer [ SECURITY](/SECURITY.md).

THE DEVELOPER WILL NOT BE RESPONSIBLE FOR ANY DAMAGES ARISING FROM THE USE OF THIS TOOL. 
THIS TOOL WAS DEVELOPED FOR EDUCATIONAL AND ETHICAL EXPERIMENTING PURPOSE ONLY .