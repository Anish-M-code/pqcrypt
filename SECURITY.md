# Limitations and Security

For any security issues in code containing in this project repo please use github issues to report security issues.
For all my personal projects in Github , i strongly believe in Full Public disclosure by making the details of security vulnerabilities public . 
I feel Public scrutiny is the only reliable way to improve security, while secrecy only makes us less secure.

While at the time of this writing there are no vulnerabilities known in any of the quantum-safe algorithms used in this tool, caution is advised when deploying quantum-safe algorithms as most of the algorithms and software have not been subject to the same degree of scrutiny as for currently deployed algorithms. Particular attention should be paid to guidance provided by the standards community, especially from the NIST Post-Quantum Cryptography Standardization project. As research advances, the supported algorithms may see rapid changes in their security, and may even prove insecure against both classical and quantum computers.

I strongly recommend to make use of so-called hybrid cryptography, in which quantum-safe public-key algorithms are used alongside traditional public key algorithms (like RSA or elliptic curves) so that the solution is at least no less secure than existing traditional cryptography.

I DO NOT CURRENTLY RECOMMEND RELYING ON THIS TOOL IN A PRODUCTION ENVIRONMENT OR TO PROTECT ANY SENSITIVE DATA. While I make a best-effort approach to avoid security bugs, this tool has not received the level of auditing and analysis that would be necessary to rely on it for high security use.