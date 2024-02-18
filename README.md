# aesni
Minimal header-only implementation of AES-256 using AES-NI instruction set

Mostly did it for the fun of it and to illustrate how does AES encryption work in a code readable step by step principle.

### Supported operation modes:
* ECB
* CBC
* CFB
* OFB

##### Supported padding modes as a little extra utility
* ANSI X9.23
* PKCS#5 and PKCS#7
* ISO/IEC 7816-4

###### ( 97.91% chances your CPU does support it, steam hw survey result as of 02.2024 )
