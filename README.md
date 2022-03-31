[![Build Status](https://travis-ci.org/zbohm/lirisi.svg?branch=master)](https://travis-ci.org/zbohm/lirisi)
[![Go Report Card](https://goreportcard.com/badge/github.com/zbohm/lirisi)](https://goreportcard.com/report/github.com/zbohm/lirisi)
[![GoDoc](https://godoc.org/github.com/zbohm/lirisi?status.svg)](https://godoc.org/github.com/zbohm/lirisi)


# Linkable Ring Signature

The project `Lirisi` implements a ring signature scheme according to the design in the document
[Linkable Spontaneous Anonymous Group Signature for Ad Hoc Groups](LSAGS-027.pdf),
written by Joseph K. Liu, Victor K. Wei and Duncan S. Wong in 2004.

## Anonymity, Linkability, Spontaneity

The scheme defines the procedure for creating and verifying an electronic signature that meets three basic requirements: anonymity, linkability and spontaneity.
**Anonymity** means that it is not possible to find out from the signature who specifically created it from the group of signatories.
**Linkability** means that it is possible to read from the signature whether another signature signed by the same signatory already exists, even though the signatory himself is not disclosed by it.
**Spontaneity** means that no one in the group of signatories is superior in the signature. Unlike a group signature, where there is a "group manager" who knows the identity of the signatories, in a ring signature, everyone is equal.

These features allow you to use a signature wherever it is desired to maintain the anonymity of the signers. For example, in electronic elections. The voter signs the selected candidate without revealing his / her identity. The voter can use only one signature, because they have a unique identifier and so any duplicates can be traced.

## Credibility, Openness, Decentralization

**Credibility** of the signature is based on asymmetric crytography. The signer always owns a pair of keys - a private key and a public key. A signature is created with the private key. Only the private key owner can create a signature. The private key must never be revealed. In contrast, the public key must be made available to everyone. Only with the help of a public key can it be verified that the signature is valid.
**The openness** of the system is ensured so that all data, except private keys, are available to everyone - public keys of signers (voters), documents to be signed (election candidates) and signatures. Thus, anyone can verify at any time that the candidates are signed with a given list of public keys and that these signatures are valid. The system cannot be attacked (hacked), because there is no data that can be manipulated or a secret that can be revealed.
**Decentralization** means that there does not necessarily have to be a central location where all data is located. Data can be in multiple places. Their location does not matter, because their validity can be verified by anyone at any time. A system designed in this way cannot be deactivated, for example by a DDos attack.

## Cryptography over elliptic curves

[Elliptic curve cryptography](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) (ECC) is used to compile the signature, which is a method of [public key encryption](https://en.wikipedia.org/wiki/Public-key_cryptography) based on [algebraic structures](https://en.wikipedia.org/wiki/Algebraic_structure) of [elliptic curves](https://en.wikipedia.org/wiki/Elliptic_curve) over [finite fields](https://en.wikipedia.org/wiki/Finite_field). There are several types of curves. Furthermore, the hash function is used when signing.

Types of curves that can be used for signing:

| Name           | [OID](https://en.wikipedia.org/wiki/Object_identifier) | Description |
| --------------- | --------------------- | ------------------------------------------- |
| prime256v1      | 1.2.840.10045.3.1.7   | X9.62/SECG curve over a 256 bit prime field |
| secp224r1       | 1.3.132.0.33          | NIST/SECG curve over a 224 bit prime field  |
| secp384r1       | 1.3.132.0.34          | NIST/SECG curve over a 384 bit prime field  |
| secp521r1       | 1.3.132.0.35          | NIST/SECG curve over a 521 bit prime field  |
| secp256k1*      | 1.3.132.0.10          | SECG curve over a 256 bit prime field       |
| brainpoolP256r1 | 1.3.36.3.3.2.8.1.1.7  | RFC 5639 curve over a 256 bit prime field   |
| brainpoolP256t1 | 1.3.36.3.3.2.8.1.1.8  | RFC 5639 curve over a 256 bit prime field   |
| brainpoolP384r1 | 1.3.36.3.3.2.8.1.1.11 | RFC 5639 curve over a 384 bit prime field   |
| brainpoolP384t1 | 1.3.36.3.3.2.8.1.1.12 | RFC 5639 curve over a 384 bit prime field   |
| brainpoolP512r1 | 1.3.36.3.3.2.8.1.1.13 | RFC 5639 curve over a 512 bit prime field   |
| brainpoolP512t1 | 1.3.36.3.3.2.8.1.1.14 | RFC 5639 curve over a 512 bit prime field   |

Types of hash functions used when signing:

| Name      | [OID](http://www.oid-info.com/index.htm) | Description                              |
| --------- | ----------------------- | --------------------------------------------------------- |
| sha3-224* | 2.16.840.1.101.3.4.2.7  | [SHA3](https://en.wikipedia.org/wiki/SHA-3)-224 algorithm |
| sha3-256* | 2.16.840.1.101.3.4.2.8  | SHA3-256 algorithm |
| sha3-384  | 2.16.840.1.101.3.4.2.9  | SHA3-384 algorithm |
| sha3-512  | 2.16.840.1.101.3.4.2.10 | SHA3-512 algorithm |

*) Only the `sha3-224` or `sha3-256` hash can be used for the `secp256k1` curve. See [ScalarBaseMult can't handle scalars > 256 bits](https://github.com/ethereum/go-ethereum/blob/v1.9.25/crypto/secp256k1/curve.go#L249).

## Implementation

The `Lirisi` project is written in [Go](https://golang.org/) as a library for use by other applications. The project includes wrappers for [Python](https://www.python.org/) and [Node.js](https://nodejs.org/).

## Use of the project

```diff
- Warning: The project is in development.
- For use in production, it is recommended to wait for the first release of version 1.0.0.
```

The project is conceived primarily as a library. It is not intended for the average user. It is expected that there will be client applications (frontends) for "end" users who will use it. The project does not address the registration of participants, the creation of keys or their distribution and verification. Nevertheless, the project also includes a simple console application for the [command line](https://en.wikipedia.org/wiki/Unix_shell). Through it, it is possible to test the entire functionality of the library. Developers in Python or Node.js can test the library via ready-made wrappers.

## Installation

To install the project, you must first have the `Go` language installed on your system. Install it from the [Go Downloads](https://golang.org/dl/). After that, the project is installed with the `go get` command:

```
$ go get github.com/zbohm/lirisi
```

Those who do not want to install the `Go` language and try the application right away can download ready-made binaries from [Nightly.link](https://nightly.link/zbohm/lirisi/workflows/go/master), compiled for the` Windows`, `MacOS` and` Ubuntu` operating systems.

## Description of using the application on the command line

The application is called with the command `lirisi`:

```
$ lirisi

Lirisi is a command line tool for creating a "Linkable ring signature".
Version: 0.0.0 (pre-release)

Commands:

  genkey      - Generate EC private key.
  pubout      - Derive public key from private key.
  fold-pub    - Fold public keys into one file.
  sign        - Sign a message or file.
  verify      - Verify signature.
  key-image   - Output the linkable value to specify a new signer.
  pub-dgst    - Output the digest of folded public keys.
  pub-xy      - Outputs X,Y coordinates of public key (binary).
  restore-pub - Decompose public keys from folded file into separate files.
  list-curves - List of available curve types.
  list-hashes - List of available hash functions.
  help        - This help or help for a specific command.

Type "lirisi help COMMAND" for a specific command help. E.g. "lirisi help fold-pub".

For more see https://github.com/zbohm/lirisi.
```

### Selection of elliptic curve type and hash function

The signatory group first agrees on the type of elliptical curve to use. For example, `prime256v1`. It also determines the type of hash function, such as `sha3-256`. Both of these values are set by default for `lirisi`, so they do not have to be specified in its commands.

### Private and public key + public keys of others

First, each participant creates their own private and public key pair. The `lirisi` application uses the` genkey` and `pubout` commands for this purpose. But you can use for example [openssl](https://www.openssl.org/) application. Creating keys via `lirisi` is compatible with` openssl`.

Creating a private key:

```
$ lirisi genkey -out my-private-key.pem
```

or alternatively

```
$ openssl ecparam -genkey -name prime256v1 -noout -out my-private-key.pem
```

Creating a public key:

```
$ lirisi pubout -in my-private-key.pem -out my-public-key.pem
```

or alternatively

```
$ openssl ec -pubout -in my-private-key.pem -out my-public-key.pem
```

For a ring signature, it is necessary to have the public keys of all other participants in the signature. After each participant creates their own key pair, the public participant sends it to everyone else or uploads it to some common repository from which the others download it. In the example, we will simulate the download of public keys to the `public-keys` folder.

Create public keys into the folder `public-keys` as if they were downloaded from the repository or passed on in another way.

```
$ mkdir public-keys
$ for name in Alice Bob Carol Dave Eve Frank George Helen Iva
do
  lirisi genkey | lirisi pubout -in - -out /tmp/public-keys/$name.pem
done
```

(or alternatively `openssl ecparam -name prime256v1 -genkey -noout | openssl ec -in - -pubout -out public-keys/$name.pem`)

We will also add our own to public keys:

```
$ cp my-public-key.pem public-keys
```

We have a private key `my-private-key.pem` and a folder` public-keys` with all public keys, including our:

```
$ ls public-keys

Alice.pem  Bob.pem  Carol.pem  Dave.pem  Eve.pem  Frank.pem  George.pem  Helen.pem  Iva.pem  my-public-key.pem
```

The private key looks like this:

```
$ cat my-private-key.pem

-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIApoL1M0U1wXM+YT7bF7y6RnBY9EwuGm02Dbr8IjuTyjoAoGCCqGSM49
AwEHoUQDQgAEa4WDUK4DCPMpNp5Wvmz+HZJ1thabxIv6Q/a68YxE58Lxd8HoQ2JF
7EX7pueGfeeQKznhzF25P8Qfe7SBs52LRw==
-----END EC PRIVATE KEY-----
```

The public key then looks like this:

```
$ cat my-public-key.pem

-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEa4WDUK4DCPMpNp5Wvmz+HZJ1thab
xIv6Q/a68YxE58Lxd8HoQ2JF7EX7pueGfeeQKznhzF25P8Qfe7SBs52LRw==
-----END PUBLIC KEY-----
```

### Creating a public keys file

Before signing, a public key file must first be created. The resulting key file is much smaller than simply merging its contents, because the values ​​are stored in it in a compressed form. In addition, values ​​common to all, such as the type of curve used, are stored in it only once. The key file is thus the smallest possible size. This is especially important in the case of a large number of signatories. Not everyone has to hand over all public keys. All one needs to do is create this key file and share it with the others. Each participant will receive only one file in which he has all the public keys. Here, however, there is a risk of other keys being spoofed, so each such key file has its own unique fingerprint, according to which everyone can verify that the file actually contains the signer's keys. The authentication method is described below in the chapter [Restore keys from the list](#restore-keys).

Another important askept of the list of keys is that **the order of the keys matters!** The unambiguity of the signature is derived from the public keys and their order. It is therefore necessary to agree on the order or to determine it in some way. The `lirisi` application implements a special sorting method that is always completely unambiguous, but still unpredictable - it cannot be inferred in advance. Therefore, none of the participants can influence the order. The method is described in detail below in the chapter [Sort keys by fingerprints](#sort-keys).

The public key file is created with the `fold-pub` command:

```
$ lirisi fold-pub -inpath public-keys -out folded-public-keys.pem
```

The resulting file looks like this:

```
$ cat folded-public-keys.pem

-----BEGIN FOLDED PUBLIC KEYS-----
CurveName: prime256v1
CurveOID: 1.2.840.10045.3.1.7
Digest: 71:b2:97:72:3e:70:d9:94:87:35:eb:64:b0:6c:7f:05:b6:ec:33:1c:91:4a:8e:b2:d2:f0:66:16:2e:00:26:34
HasherName: sha3-256
HasherOID: 2.16.840.1.101.3.4.2.8
NumberOfKeys: 10
Origin: github.com/zbohm/lirisi

MIIBvhMjZ2l0aHViLmNvbS96Ym9obS9saXJpc2kgUHVibGljIGtleXMGCCqGSM49
AwEHBglghkgBZQMEAggEIHGyl3I+cNmUhzXrZLBsfwW27DMckUqOstLwZhYuACY0
MIIBXgQhA4FkwtsTE51Bt8vDwvLqzOr9Wo/23Srlb/Htcnwh5l0nBCEDNFsxfvuo
3cnf5KUCySuifRlAoV7ZSb235MOTJIUaq7IEIQMwCLpQTQuup93hLvWPP/9fmgY1
mQepaNgI7UW1EAVRTwQhAxEG42wot9WoYnT4uEkG9/k04DsVCz7PnRxkD6wshoeG
BCECQLA/gChaoBiC0y2n/Cy2DmYxjAijsosLRGBkHK6fXNkEIQNrhYNQrgMI8yk2
nla+bP4dknW2FpvEi/pD9rrxjETnwgQhA/5d+KLKdDsz9as7gqVVUN9MiPhXgGcf
p5U9VORrbsctBCEDr97Q1TrQVTNukfiCmF/ofm2LmcrWRSF/6y2NJOJXDGkEIQPT
ERzuMDD//2xqCdLe4rEraudLNrjBpN6+1heLODkXWQQhA9/2pDlVKhyqnX3gZExy
fHL/t4pupI67lrX3DEcd78nL
-----END FOLDED PUBLIC KEYS-----
```

### Creating a signature

The signature is created with the `sign` command. We can sign either a statement or a file.

Example of signing the text `Hello, world!`:

```
$ lirisi sign -message 'Hello, world!' -inpub folded-public-keys.pem -inkey my-private-key.pem -out signature.pem
```

The following signature is created:

```
$ cat signature.pem

-----BEGIN RING SIGNATURE-----
CurveName: prime256v1
CurveOID: 1.2.840.10045.3.1.7
HasherName: sha3-256
HasherOID: 2.16.840.1.101.3.4.2.8
KeyImage:
  1a:3a:56:52:0b:a2:20:42:2b:ec:85:44:eb:6a:3e:2e
  29:00:16:2c:4b:6f:7d:67:7f:ba:e7:9d:2b:5f:83:fa
  b1:b6:16:10:9a:9c:8e:76:f4:cd:63:3f:86:93:cd:04
  fe:06:14:45:9a:1e:d9:1d:56:d2:25:77:de:1e:dd:02
NumberOfKeys: 10
Origin: github.com/zbohm/lirisi

MIIB+xMhZ2l0aHViLmNvbS96Ym9obS9saXJpc2kgU2lnbmF0dXJlAgEBBggqhkjO
PQMBBwYJYIZIAWUDBAIIMEQEIBo6VlILoiBCK+yFROtqPi4pABYsS299Z3+6550r
X4P6BCCxthYQmpyOdvTNYz+Gk80E/gYURZoe2R1W0iV33h7dAgQgUxoLYy+XcTCv
WJ/NS/Ofrc3XplMNaJxHWjxz9YfNvREwggFUBCBXZ3h6ePkNskKv6FYZ1/3HZOzA
KonhaNsuKbXT4Ljy2gQgCCBqEXoSG5OV3lMKUwc4QbhwkUuLYwQXMRgRuuB8crIE
IAPyph3mY+qyeMtsG42ec+HCR7Xzb+mUH7I5ka4xTf73BCB7zGdfkjsBnXaXPE8i
7PXhYKDyamfLmzFS6HOm/0Af2AQgQnpZywoZJbZfU2Xql1CCI9+NYWpsPFYba5tz
4IsnC4MEIP5DBw97peW2tcDzOHU00JtvNegVGj1Ci21ky2Ifd+62BCCJowQl+b4C
oaCs7cf7nqnfYLR64lP7PY/kX+7olHiw9gQgTu00L2HOz6BQ0+S5ODJ9dOWd7U8g
+ysanafTF2weh7cEIN2ltMDOWbenRaOeG3T3Z5JxP4fyItb62fhbQZGdf9wdBCAf
2RtfJtVdZp/+To1GD69Boiqos81hlDymMs4fufdLSg==
-----END RING SIGNATURE-----
```

If a document needs to be signed, its name will be specified in the `-message` parameter. For example: `-message ./path/document.pdf`.

#### Parameter `case` for distinguishing duplicate signatures

Recognition of duplicate signatures (uniqueness of the signer) is based on a comparison of the list of public keys. In order to be able to create more non-duplicate signatures when voting, you can set a value when signing via the `-case` parameter, which will prevent duplication for the given list. For example, this can be used for multi-round voting. Then the unambiguity will exist only for the given round and the participant can create one signature for each round:

```
$ lirisi sign -message 'Hello, world!' -case 'The first round of voting' ...
$ lirisi sign -message 'Hello, world!' -case 'Second round of voting' ...
```

### Ring signature verification

The signature is verified with the command `verify`:

```
$ lirisi verify -message 'Hello, world!' -inpub folded-public-keys.pem -in signature.pem
Verified OK

$ lirisi verify -message 'Hello, world?' -inpub folded-public-keys.pem -in signature.pem
Verification Failure
```

### PEM and DER input / output formats

The default format for the key file and signature is [PEM](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail). It is a text format, suitable for saving to a database, for example. In addition, the [DER](https://en.wikipedia.org/wiki/X.690#DER_encoding) binary file can be used. You set the format with the `-format` parameter, for example: `-format DER`. The private and public keys generated via `openssl` can also be stored in the `DER` format. The application recognizes it and can load it.

### KeyImage value to determine the duplicity of the signer

The `KeyImage` value in the signature uniquely identifies the signer. It is a de facto anonymous unique identifier of the signer. It appears in `PEM` format after the name` KeyImage`:

```
$ cat signature.pem

-----BEGIN RING SIGNATURE-----
  ...
KeyImage:
  1a:3a:56:52:0b:a2:20:42:2b:ec:85:44:eb:6a:3e:2e
  29:00:16:2c:4b:6f:7d:67:7f:ba:e7:9d:2b:5f:83:fa
  ....
```

However, this is just a simple text that could be falsified. A credible entry is read from the signature with the command `key-image`:

```
$ lirisi key-image -in signature.pem

1a3a56520ba220422bec8544eb6a3e2e290016...
```

The value displayed in this way is difficult for human to read, so it is possible to add a delimiter to it via the `-c` parameter:

```
$ lirisi key-image -c -in signature.pem

1a:3a:56:52:0b:a2:20:42:2b:ec:85:44:eb:6a:3e:2e:29:00:16...
```

### Key list fingerprint

The key list also has its own unique fingerprint, which can be used to identify it. It appears after the name `Digest`:

```
$ cat folded-public-keys.pem

-----BEGIN FOLDED PUBLIC KEYS-----
  ...
Digest: 71:b2:97:72:3e:70:d9:94:87:35:eb:64:b0:6c:7f:05:b6:ec:33:1c:91:4a:8e:b2:d2:f0:66:16:2e:00:26:34
  ...
```

As with the signature, however, this value is just plain text that could be underlined. A reliable entry is printed with the command `pub-dgst`:

```
$ lirisi pub-dgst -in folded-public-keys.pem
71b297723e70d9948735eb64b06c7f05b6ec331c914a8eb2d2f066162e002634

$ lirisi pub-dgst -c -in folded-public-keys.pem
71:b2:97:72:3e:70:d9:94:87:35:eb:64:b0:6c:7f:05:b6:ec:33:1c:91:4a:8e:b2:d2:f0:66:16:2e:00:26:34
```

### <a name="restore-keys">Restore keys from the list</a>

If you suspect that the key list is manipulated or only when checking it, you can remove the keys from the list and restore them to the original separate files. Then each of them can be compared with the original key, if it is identical. To restore the keys, use the `restore-pub` command. The files are saved in the selected folder, for example `restored-keys`. The default format is `PEM`.

```
$ mkdir restore-pub
$ lirisi restore-pub --in folded-public-keys.pem -outpath restore-pub
10 public keys saved into restore-pub.
```

The original keys are stored in the `public-keys` folder. We find a match by comparing the contents of all the files in these two folders. Depending on the file names, this cannot be done because they are not saved to the list when merged.

```
$ find public-keys -type f -exec md5sum {} + > dir1.txt
$ find restore-pub -type f -exec md5sum {} + > dir2.txt

$ while read line
do
  hash=`echo $line | awk '{print $1}'`
  name=`echo $line | awk '{print $2}'`
  sed -i "s|$hash |$hash $name|" dir1.txt
done < dir2.txt

$ cat dir1.txt

500ece1452eae81d60880e635e639dbc restore-pub/public-key-03.pem public-keys/Bob.pem
3b57281818eda2af1f0f5d71105dfb57 restore-pub/public-key-04.pem public-keys/Helen.pem
c50decd521cf9902b8da7958ce02896d restore-pub/public-key-08.pem public-keys/George.pem
07b7aec69e5d516aceb77f46700f8986 restore-pub/public-key-02.pem public-keys/Alice.pem
879412e39f9c375f2add8f3426e37f2b restore-pub/public-key-10.pem public-keys/Eve.pem
b6ef9d09ed72aeb4026ee22e820e3371 restore-pub/public-key-05.pem public-keys/Iva.pem
93c63ffc3bd0fd42f3906fd1c52d9023 restore-pub/public-key-01.pem public-keys/Frank.pem
5dd7f5ae325977c18f63b6a30497fddd restore-pub/public-key-07.pem public-keys/Carol.pem
e0dfa849d907cc6f725bafc532111a9b restore-pub/public-key-06.pem public-keys/my-public-key.pem
58e06bf36bea38092218f1aab548b38e restore-pub/public-key-09.pem public-keys/Dave.pem
```



### <a name="sort-keys">Sort keys by fingerprints</a>

The order of the public keys is important because it identifies the identifiers of the signers. The rule for determining the order of keys must be unambiguous. Furthermore, it should be as uncontrollable as possible so that it is not possible to manipulate the order in any way. By default, the `fold-pub` command sorts keys by fingerprints of the X, Y values of public keys. The sort fingerprint has a good "salt" calculated from the list of fingerprints of all keys. You can only sort keys if they all exist.

The key file `folded-public-keys.pem` has the fingerprint` 71b297723e70d9948735 ... `

```
$ cat folded-public-keys.pem

-----BEGIN FOLDED PUBLIC KEYS-----
  ...
Digest: 71:b2:97:72:3e:70:d9:94:87:35:eb:64:b0:6c:7f:05:b6:ec:33:1c:91:4a:8e:b2:d2:f0:66:16:2e:00:26:34
HasherName: sha3-256
  ...
```

The fingerprint calculation can also be reproduced in [Bash](https://en.wikipedia.org/wiki/Bash_(Unix_shell)) on the [command line](https://en.wikipedia.org/wiki/Unix_shell). From the list of values `HasherName` we see that the hash function `sha3-256` was used. Therefore, we will use this function for fingerprint calculations.

The X, Y values are the coordinates of the point on the elliptic curve. The public key consists of these two numbers. The bytes of these two numbers can be listed with the `pub-xy` command. Because these are binary data, we can interpret them on the console via the `hexdump` filter:

```
$ lirisi pub-xy -in my-public-key.pem | hexdump -C

00000000  04 6b 85 83 50 ae 03 08  f3 29 36 9e 56 be 6c fe  |.k..P....)6.V.l.|
00000010  1d 92 75 b6 16 9b c4 8b  fa 43 f6 ba f1 8c 44 e7  |..u......C....D.|
00000020  c2 f1 77 c1 e8 43 62 45  ec 45 fb a6 e7 86 7d e7  |..w..CbE.E....}.|
00000030  90 2b 39 e1 cc 5d b9 3f  c4 1f 7b b4 81 b3 9d 8b  |.+9..].?..{.....|
00000040  47                                                |G|
```

The `openssl` program can only print the bytes of a public key from a private key. For a public key without knowing the private one, `pub-xy` or another utility must be used.

```
$ openssl ec -text -noout -in my-private-key.pem

read EC key
Private-Key: (256 bit)
priv:
    0a:68:2f:53:34:53:5c:17:33:e6:13:ed:b1:7b:cb:
    a4:67:05:8f:44:c2:e1:a6:d3:60:db:af:c2:23:b9:
    3c:a3
pub:
    04:6b:85:83:50:ae:03:08:f3:29:36:9e:56:be:6c:
    fe:1d:92:75:b6:16:9b:c4:8b:fa:43:f6:ba:f1:8c:
    44:e7:c2:f1:77:c1:e8:43:62:45:ec:45:fb:a6:e7:
    86:7d:e7:90:2b:39:e1:cc:5d:b9:3f:c4:1f:7b:b4:
    81:b3:9d:8b:47
ASN1 OID: prime256v1
NIST CURVE: P-256
```

From these two listings, you can verify the match - that these are indeed public key bytes:

```
00000000  04 6b 85 83 50 ae 03 08  f3 29 36 9e 56 be 6c fe  |.k..P....)6.V.l.|
pub:      04:6b:85:83:50:ae:03:08: f3:29:36:9e:56:be:6c:fe:
```

So we will create a list with public key prints and sort it according to them:

```
$ for pkey in public-keys/*
do
    lirisi pub-xy -in $pkey | openssl dgst -sha3-256 - | awk '{print $2}'
done > public-keys-hashes.txt

$ LC_ALL=C sort public-keys-hashes.txt > sorted-hashes.txt
```

In the file `sorted-hashes.txt` we have a list from which we get a fingerprint, which we store in the variable `summary`:

```
$ summary=`openssl dgst -sha3-256 sorted-hashes.txt | awk '{print $2}'`
```

We will use the value `summary` as "salt". We'll associate it with the imprint of each key. From this combined value, we will create a new fingerprint. The keys are then sorted according to this new fingerprint.

Creating new fingerprints with `summary` as "salt":

```
$ while read code
do
    digest=`echo -n $summary$code | openssl dgst -sha3-256 | awk '{print $2}'`
    echo "$digest $code"
done < public-keys-hashes.txt > digests.txt
```

Sort keys by new fingerprints and calculate the final fingerprint for folded keys:

```
$ LC_ALL=C sort digests.txt | awk '{print $2}' | openssl dgst -sha3-256 -c | awk '{print $2}'
71:b2:97:72:3e:70:d9:94:87:35:eb:64:b0:6c:7f:05:b6:ec:33:1c:91:4a:8e:b2:d2:f0:66:16:2e:00:26:34
```

This value corresponds to the `Digest` data in the key file and the extract from the` pub-dgst` command:

```
$ lirisi pub-dgst -c -in folded-public-keys.pem
71:b2:97:72:3e:70:d9:94:87:35:eb:64:b0:6c:7f:05:b6:ec:33:1c:91:4a:8e:b2:d2:f0:66:16:2e:00:26:34
```

### Sort keys by fingerprints

```
$ for key in public-keys/*
do
    name=`basename $key`
    code=`lirisi pub-xy -in $key | openssl dgst -sha3-256 - | awk '{print $2}'`
    digest=`echo -n $summary$code | openssl dgst -sha3-256 | awk '{print $2}'`
    echo "$digest $name"
done > digest-public-keys.txt

$ LC_ALL=C sort digest-public-keys.txt | awk '{print $2}'

Frank.pem
Alice.pem
Bob.pem
Helen.pem
Iva.pem
my-public-key.pem
Carol.pem
George.pem
Dave.pem
Eve.pem
```

The order of the keys corresponds to the list we obtained when [restoring the keys](#restore-keys).

```
$ awk '{print $2 " " $3}' dir1.txt | sort | awk '{print $2}'

public-keys/Frank.pem
public-keys/Alice.pem
public-keys/Bob.pem
public-keys/Helen.pem
public-keys/Iva.pem
public-keys/my-public-key.pem
public-keys/Carol.pem
public-keys/George.pem
public-keys/Dave.pem
public-keys/Eve.pem
```

## Library

Example of using a library in `Go`:


```go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"hash"
	"log"

	"github.com/zbohm/lirisi/client"
	"github.com/zbohm/lirisi/ring"
)

func encodePublicKeyToDer(key *ecdsa.PublicKey) []byte {
	derKey, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		log.Fatal(err)
	}
	return derKey
}

// Auxiliary function for creating public keys.
func createPublicKeyList(curve elliptic.Curve, size int) []*ecdsa.PublicKey {
	publicKeys := make([]*ecdsa.PublicKey, size)
	for i := 0; i < size; i++ {
		privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		publicKeys[i] = privateKey.Public().(*ecdsa.PublicKey)
	}
	return publicKeys
}

func createPrivateAndPublicKeyExample() {
	// Create private key
	status, privateKey := client.GeneratePrivateKey("prime256v1", "PEM")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("%s", privateKey)
	// Create public key.
	status, publicKey := client.DerivePublicKey(privateKey, "PEM")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("%s", publicKey)
}

func baseExample(
	curveType func() elliptic.Curve,
	hashFnc func() hash.Hash,
	privateKey *ecdsa.PrivateKey,
	publicKeys []*ecdsa.PublicKey,
	message, caseIdentifier []byte,
) ([]byte, []byte) {
	// Make signature.
	status, signature := ring.Create(curveType, hashFnc, privateKey, publicKeys, message, caseIdentifier)
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}

	// Verify signature.
	status = ring.Verify(signature, publicKeys, message, caseIdentifier)
	if status == ring.Success {
		fmt.Println("Signature verified OK")
	} else {
		fmt.Println("Signature verification Failure")
	}

	// Encode signature to format DER.
	status, signatureDer := client.EncodeSignarureToDER(signature)
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Signature in DER:\n%s\n", hex.Dump(signatureDer))

	// Encode signature to format PEM.
	status, signaturePem := client.EncodeSignarureToPEM(signature)
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Signature in PEM:\n%s\n", signaturePem)
	return signatureDer, signaturePem
}

func foldedKeysExample(privateKey *ecdsa.PrivateKey, foldedPublicKeys, signatureDer, signaturePem, message, caseIdentifier []byte) {
	// Verify signature in DER.
	status := client.VerifySignature(foldedPublicKeys, signatureDer, message, caseIdentifier)
	if status == ring.Success {
		fmt.Println("Signature in DER: Verified OK")
	} else {
		fmt.Println("Signature in DER: Verification Failure")
	}
	// Verify signature in PEM.
	status = client.VerifySignature(foldedPublicKeys, signaturePem, message, caseIdentifier)
	if status == ring.Success {
		fmt.Println("Signature in PEM: Verified OK")
	} else {
		fmt.Println("Signature in PEM: Verification Failure")
	}

	// Encode private key to DER.
	privateKeyDer, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		log.Fatal(err)
	}
	// Make first signature in format DER.
	status, signatureDer = client.CreateSignature(foldedPublicKeys, privateKeyDer, message, caseIdentifier, "DER")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Signature in DER Nr.2:\n\n%s\n", hex.Dump(signatureDer))
	// Verify signature in DER.
	status = client.VerifySignature(foldedPublicKeys, signatureDer, message, caseIdentifier)
	if status == ring.Success {
		fmt.Println("Signature in DER Nr.2: Verified OK")
	} else {
		fmt.Println("Signature in DER Nr.2: Verification Failure")
	}

	// Make second signature in format PEM.
	status, signaturePem = client.CreateSignature(foldedPublicKeys, privateKeyDer, message, caseIdentifier, "PEM")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Signature in PEM:\n\n%s\n", signaturePem)
	// Verify signature in PEM.
	status = client.VerifySignature(foldedPublicKeys, signaturePem, message, caseIdentifier)
	if status == ring.Success {
		fmt.Println("Signature in PEM Nr.2: Verified OK")
	} else {
		fmt.Println("Signature in PEM Nr.2: Verification Failure")
	}
	fmt.Println()
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Choose curve type.
	curveType := elliptic.P256
	// Choose hash type.
	hashName := "sha3-256"
	hashFnc, ok := ring.HashCodes[hashName]
	if !ok {
		log.Fatal(ring.UnexpectedHashType)
	}

	createPrivateAndPublicKeyExample()

	// Creating public keys as a simulation of keys supplied by other signers.
	publicKeys := createPublicKeyList(curveType(), 9)

	// Create your private key.
	privateKey, err := ecdsa.GenerateKey(curveType(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	// Add your public key to other public keys.
	publicKey := privateKey.Public().(*ecdsa.PublicKey)
	publicKeys = append(publicKeys, publicKey)

	status, coordinates := client.PublicKeyXYCoordinates(encodePublicKeyToDer(publicKey))
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Coordinates of public key:\n%s\n", hex.Dump(coordinates))

	message := []byte("Hello world!")
	caseIdentifier := []byte("Round Nr.1")

	signatureDer, signaturePem := baseExample(curveType, hashFnc, privateKey, publicKeys, message, caseIdentifier)

	// Encode public keys to DER.
	publicKeysDer := [][]byte{}

	for _, key := range publicKeys {
		publicKeysDer = append(publicKeysDer, encodePublicKeyToDer(key))
	}

	// Create the content of file with public keys.
	status, foldedPublicKeys := client.FoldPublicKeys(publicKeysDer, hashName, "DER", "notsort")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Public keys in DER:\n%s\n", hex.Dump(foldedPublicKeys))
	// Display fingerprint of public keys in format PEM.
	status, digest := client.PublicKeysDigest(foldedPublicKeys, true)
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Public keys digest: %s\n\n", digest)

	// Display fingerprint of public keys in format DER.
	status, foldedPublicKeysPEM := client.FoldPublicKeys(publicKeysDer, hashName, "PEM", "notsort")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Keys from DER:\n%s\n", foldedPublicKeysPEM)

	foldedKeysExample(privateKey, foldedPublicKeys, signatureDer, signaturePem, message, caseIdentifier)

	// Decompose folded public keys into files.
	status, unfoldedPublicKeys := client.UnfoldPublicKeysIntoBytes(foldedPublicKeys, "PEM")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	for i, pubKey := range unfoldedPublicKeys {
		fmt.Printf("%d. public key:\n%s\n", i+1, pubKey)
	}
}
```

### Library for other programming languages

The [lib/lirisilib.go](https://github.com/zbohm/lirisi/blob/master/lib/lirisilib.go) library is ready for use in other programming languages.

You need to compile it with the `-buildmode = c-shared` switch. This will create a binary and a header file:

```
$ go build -o wrappers/lirisilib.so -buildmode=c-shared lib/lirisilib.go
```

`Lirisi` has wrappers ready for this library, for [Python](https://www.python.org/) (> = 3.5) and for [Node.js](https://nodejs.org/).


#### Python

Wrapper for [Python](https://www.python.org/) (verze >= 3.5) is ready in folder `wrappers/python/lirisi/`.
Before using it for the first time, copy the binary to it or refer to it in the symlink:

```
$ ln -s ../../lirisilib.so wrappers/python/lirisi/lirisilib.so
```

There is a usage example in the `example.py` file. It uses the `cryptography` module.
If you do not have it installed, install it, eg via `pip install cryptography`.

Go to the `wrappers / python` folder and run the example:` python example.py`:

```python
from typing import Callable, List

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from lirisi import (CreateSignature, DerivePublicKey, FoldPublicKeys,
                    GeneratePrivateKey, LirisiException, PublicKeysDigest,
                    PublicKeyXYCoordinates, SignatureKeyImage,
                    UnfoldPublicKeys, VerifySignature)


def createPublicKeyList(backend: Callable, curve: ec.EllipticCurve, size: int) -> List[bytes]:
    public_keys_pem = []
    for i in range(size):
        private_key = ec.generate_private_key(curve, backend)
        public_key = private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        public_keys_pem.append(pem)
    return public_keys_pem


def main():
    backend = default_backend()

    # Create private key. Default curve type is "prime256v1".
    priateKeyPem = GeneratePrivateKey()
    print(priateKeyPem.decode())

    # Create public key.
    publicKeyPem = DerivePublicKey(priateKeyPem)
    print(publicKeyPem.decode())

    # Choose curve type.
    curve = ec.SECP256R1()

    # Creating public keys as a simulation of keys supplied by other signers.
    public_keys_pem = createPublicKeyList(backend, curve, 9)

    # Create your private key.
    private_key = ec.generate_private_key(curve, backend)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    print(private_key_pem.decode())

    # Add your public key to other public keys.
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    public_keys_pem.append(public_key_pem)

    coordinates = PublicKeyXYCoordinates(public_key_pem)
    print("Public key coordinates (bytes):\n", coordinates, "\n")

    # Create the content of file with public keys.
    foldedPublicKeys = FoldPublicKeys(public_keys_pem)
    print(foldedPublicKeys.decode())

    # Display fingerprint of public keys.
    digest = PublicKeysDigest(foldedPublicKeys, True)
    print("Public keys digest:", digest.decode())
    print()

    # Make signature.
    signature = CreateSignature(foldedPublicKeys, private_key_pem, b'Hello, world!')
    print(signature.decode())

    # Verify signature.
    if VerifySignature(foldedPublicKeys, signature, b'Hello, world!'):
        print("Signature verified OK")
    else:
        print("Signature verification Failure")
    print()

    # Display Signer identifier KeyImage.
    key_image = SignatureKeyImage(signature, True)
    print("KeyImage:", key_image)
    print()

    unfolded_keys = UnfoldPublicKeys(foldedPublicKeys)
    for pos, key in enumerate(unfolded_keys):
        print("public-key-{:>02d}.pem".format(pos + 1))
        print(key.decode())


if __name__ == "__main__":
    try:
        main()
    except LirisiException as err:
        print(err)
```

#### Node.js

Wrapper for [Node.js](https://nodejs.org/) is ready in folder `wrappers/nodejs/lirisi/`.
Before using it for the first time, copy the binary to it or refer to it in the symlink:

```
$ ln -s ../../lirisilib.so wrappers/nodejs/lirisi/lirisilib.so
```

There is a usage example in the `example.js` file.
Go to the `wrapper/nodejs` folder:

```
$ cd wrappers/nodejs
```

Before running for the first time, install the necessary packages:

```
$ npm install
```

Note: If you get a `npm ERR! ref@1.3.5 install: node-gyp rebuild`, so try to update your OS:

```
npm install --global npm@latest
npm install --global node-gyp@latest
npm config set node_gyp $(npm prefix -g)/lib/node_modules/node-gyp/bin/node-gyp.js
```

You can now run the demo:

```
$ node example.js
```

```javascript
var Eckles = require('eckles')
const lirisi = require('lirisi')


const main = async () => {
    // Create private key.
    const privatePem = lirisi.GeneratePrivateKey("prime256v1")
    console.log("Curve type prime256v1:\n", lirisi.ArrayToString(privatePem))

    // Create public key.
    const publicPem = lirisi.DerivePublicKey(privatePem)
    console.log(lirisi.ArrayToString(publicPem))

    // Creating public keys as a simulation of keys supplied by other signers.
    const publicKeysPEM = []
    for (let i = 0; i < 9; i++) {
        const pair = await Eckles.generate({format: 'pem'})
        publicKeysPEM.push(pair.public)
    }

    // Create your private and public key.
    const pair = await Eckles.generate({format: 'pem'})
    const privateKeyPEM = pair.private
    const publicKeyPEM = pair.public
    console.log("Eckles.generate:\n", privateKeyPEM, "\n")

    const coordinates = lirisi.PublicKeyXYCoordinates(publicKeyPEM)
    console.log("Puplic key coordinates:\n", Buffer.from(coordinates).toString('hex'), "\n")

    // Add your public key to other public keys.
    publicKeysPEM.push(publicKeyPEM)

    // Create the content of file with public keys.
    const foldedPublicKeys = lirisi.FoldPublicKeys(publicKeysPEM)
    console.log(lirisi.ArrayToString(foldedPublicKeys))

    // Display fingerprint of public keys.
    console.log("Digest:", lirisi.PublicKeysDigest(foldedPublicKeys, true), "\n")

    const message = 'Hello, world!'

    // Make signature.
    const signature = lirisi.CreateSignature(foldedPublicKeys, privateKeyPEM, message)
    console.log(lirisi.ArrayToString(signature))

    // Verify signature.
    const result = lirisi.VerifySignature(foldedPublicKeys, signature, message)
    console.log(lirisi.ResultMessage(result), "\n")

    console.log("KeyImage:", lirisi.SignatureKeyImage(signature, true), "\n")

    const unfoldedPublicKeys = lirisi.UnfoldPublicKeys(foldedPublicKeys)
    for(let i = 0; i < unfoldedPublicKeys.length; i++) {
        console.log(
            'public-key-' + (i + 1).toString().padStart(2, "0") + '.pem\n',
            lirisi.ArrayToString(unfoldedPublicKeys[i])
        )
    }
}

main().catch((e) => {
    console.error(e)
})
```

### Code viewing

Some "Literate programming" style source code is available at https://zbohm.github.io/lirisi/.
A description of the implementation of the signature according to the scheme is in section
[4 A LSAG Signature Scheme](https://zbohm.github.io/lirisi/signature_factory.html#section-25).

### License

Viz [LICENSE](/LICENSE).
