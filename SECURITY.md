# Security Policy

For any security issues in code containing in this project repo please use github issues to report security issues.
For all my personal projects in Github , i strongly believe in Full Public disclosure by making the details of security vulnerabilities public . 
I feel Public scrutiny is the only reliable way to improve security, while secrecy only makes us less secure.

While at the time of this writing there are no vulnerabilities known in any of the quantum-safe algorithms used in this tool, caution is advised when deploying quantum-safe algorithms as most of the algorithms and software have not been subject to the same degree of scrutiny as for currently deployed algorithms. Particular attention should be paid to guidance provided by the standards community, especially from the NIST Post-Quantum Cryptography Standardization project. As research advances, the supported algorithms may see rapid changes in their security, and may even prove insecure against both classical and quantum computers.

I strongly recommend to make use of so-called hybrid cryptography, in which quantum-safe public-key algorithms are used alongside traditional public key algorithms (like RSA or elliptic curves) so that the solution is at least no less secure than existing traditional cryptography.

Also kindly periodically check https://github.com/Anish-M-code/pqcrypt/issues for known security issues and follow possible workarounds to mitigate it . Further like all other software check for updates in this github repository and always use latest code from this github repository for optimal security.

# Known Limitations

I DO NOT CURRENTLY RECOMMEND RELYING ON THIS TOOL IN A PRODUCTION ENVIRONMENT OR TO PROTECT ANY SENSITIVE DATA. While I make a best-effort approach to avoid security bugs, this tool has not received the level of auditing and analysis that would be necessary to rely on it for high security use.

No Secure memory wiping

Memory wiping is used to protect secret data or key material from attackers with access to deallocated memory. This is a defense-in-depth measure against vulnerabilities that leak application memory. This feature is not present in PQcrypt as it uses python's cryptography package where secure memory wiping is not present.
cryptography python package does not clear memory by default, as there is no way to clear immutable structures such as bytes. As a result, like almost all software in Python, it is potentially vulnerable to this attack. The CERT secure coding guidelines assesses this issue as “Severity: medium, Likelihood: unlikely, Remediation Cost: expensive to repair” and we do not consider this a high risk for most users.

Additionally please don't use this tool to encrypt very huge files / process huge public keys in order of Giga bytes, this program will simply load the entire file in RAM or main memory and this may cause freezing of your PC , Application crash or have unwanted side effects.
However this program is memory safe to use for signing and verifying Post Quantum Digital Signatures for large files .
