# fakeYubi
Prototypical software authenticator for use with Web Authentication
# Acknowledgements

fakeYubi is based on the work of Andrey Konovalov (raw_gadget: https://github.com/xairy/raw-gadget).


Needed files where included in this repository out of necessity.

# Usage

Download the files and execute fakeYubi.sh inside root folder:\
```sudo fakeYubi.sh```\
At the moment root rights are necessary to load the kernelmodules and install dependencies (e.g. libcbor-dev) to build the binary files.\
\
A new instance of fakeYubi should be running in the terminal now.\
Navigate to a Web Authentication enabled site (for example webauthn.io) and you should be able to register.\
\
As it's a prototype, the CTAP2 protocoll is only implemented till finishing a registration. No actual authentication can be done for now.\
Only fully cbor message enabled browsers, as chrome, are supported yet. That means no backwards Compatibility to U2F is done.

# Pre-Build Version

An experimental pre-build version of fakeyubi has been added for testing purposes. It was build on Ubuntu 18.04 with Linux version 5.3.0-62 and as such should only work on Systems running the same kernel version. To use just execute fakeYubi_prebuilt.sh:\
```sudo fakeYubi_prebuilt.sh```\
USE AT OWN RISK!
