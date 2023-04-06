# rsa-archer-for-soar
The initial primary reason to develop this app is the RSA Archer API(s) does not support HTTP Basic Authentication to allow use of the HTTP app for custom actions. The RSA Archer API(s) uses its own authentication scheme.

# Security Note
It should be noted that RSA Archer API credentials can be exposed within the user space for the "get session token" and "terminate session" actions; so it is recommended to implement the proper access controls depending on your use case.
