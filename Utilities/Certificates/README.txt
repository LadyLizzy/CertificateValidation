This folder contains the certificates used in this example.
In order for it to work install the:
- CARoot.cer certificate in your Local Machine Trusted Root Certification Authorities store
- ServerCert.pfx certificate in your Local Machine Personal store
- ClientCert.pfx certificate in your Current User OR Local Machine store REMEMBER to change the store accordingly in the Client's GetClientCertificates() method.