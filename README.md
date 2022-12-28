# sign-file
Rust version of sign tool for kernel module, see: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/scripts/sign-file.c

# Command help
```shell
Command to sign kernel module file with x509 certificate

Usage: sign-file [OPTIONS] [COMMAND]

Commands:
  produce  Sign ko file as well as generate detached signature file (*.p7s)
  detach   Sign ko file with only generate detached signature file (*.p7s)
  raw      Append raw signature to ko file
  help     Print this message or the help of the given subcommand(s)

Options:
      --debug    
  -h, --help     Print help information
  -V, --version  Print version information

```

# TODO
1. Support key id
2. Support digest algorithm

# Background

## How to inspect p7s file
```shell
tommylike@ubuntu ~ openssl asn1parse -inform der -in <detached p7s file>
    0:d=0  hl=4 l= 395 cons: SEQUENCE
    4:d=1  hl=2 l=   9 prim: OBJECT            :pkcs7-signedData
   15:d=1  hl=4 l= 380 cons: cont [ 0 ]
   19:d=2  hl=4 l= 376 cons: SEQUENCE
   23:d=3  hl=2 l=   1 prim: INTEGER           :01
   26:d=3  hl=2 l=  13 cons: SET
   28:d=4  hl=2 l=  11 cons: SEQUENCE
   30:d=5  hl=2 l=   9 prim: OBJECT            :sha256
   41:d=3  hl=2 l=  11 cons: SEQUENCE
   43:d=4  hl=2 l=   9 prim: OBJECT            :pkcs7-data
   54:d=3  hl=4 l= 341 cons: SET
   58:d=4  hl=4 l= 337 cons: SEQUENCE
   62:d=5  hl=2 l=   1 prim: INTEGER           :01
   65:d=5  hl=2 l=  44 cons: SEQUENCE
   67:d=6  hl=2 l=  20 cons: SEQUENCE
   69:d=7  hl=2 l=  18 cons: SET
   71:d=8  hl=2 l=  16 cons: SEQUENCE
   73:d=9  hl=2 l=   3 prim: OBJECT            :commonName
   78:d=9  hl=2 l=   9 prim: UTF8STRING        :YOUR_NAME
   89:d=6  hl=2 l=  20 prim: INTEGER           :166DE55F82FA7E7998617A07F81FBADC63A7CAFD
  111:d=5  hl=2 l=  11 cons: SEQUENCE
  113:d=6  hl=2 l=   9 prim: OBJECT            :sha256
  124:d=5  hl=2 l=  13 cons: SEQUENCE
  126:d=6  hl=2 l=   9 prim: OBJECT            :rsaEncryption
  137:d=6  hl=2 l=   0 prim: NULL
  139:d=5  hl=4 l= 256 prim: OCTET STRING      [HEX DUMP]:<A Large number of Hex values>
```
## A utility to verify the kernel module signature
Reference: https://unix.stackexchange.com/questions/493170/how-to-verify-a-kernel-module-signature