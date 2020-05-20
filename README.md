# Virgil Crypto Library Objective-C/Swift

[![Build Status](https://api.travis-ci.com/VirgilSecurity/virgil-crypto-x.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-crypto-x)
[![CocoaPods Compatible](https://img.shields.io/cocoapods/v/VirgilCrypto.svg)](https://img.shields.io/cocoapods/v/VirgilCrypto.svg)
[![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)
![Platform](https://img.shields.io/cocoapods/p/VirgilCrypto.svg?style=flat)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

[Introduction](#introduction) | [Library purposes](#library-purposes) | [Installation](#installation) | [Usage examples](#usage-examples) | [Docs](#docs) | [License](#license) | [Contacts](#support)

## Introduction

Virgil Crypto Library Objective-C/Swift is a small, flexible and convenient wrapper for a variety of crypto algorithms. It can be used in a small microcontroller as well as in a high load server application. Also, it provides a bunch of custom hybrid algorithms that combine different crypto algorithms to solve common complex cryptographic problems in an easy way. That eliminates a requirement for developers to have strong cryptographic skills.

Virgil Security Objective-C/Swift Crypto Library uses Swift wrapper [Virgil Security Crypto Library Wrapper](https://github.com/VirgilSecurity/virgil-cryptowrapper-x) over C library [Virgil Security Crypto Library](https://github.com/VirgilSecurity/virgil-crypto-c). 

## Library purposes

* Asymmetric Key Generation
* Encryption/Decryption of data and streams
* Generation/Verification of digital signatures
* Double Ratchet algorithm support
* **Post-quantum algorithms support**: [Round5](https://round5.org/) (encryption) and [Falcon](https://falcon-sign.info/) (signature) 
* Crypto for using [Virgil Core SDK](https://github.com/VirgilSecurity/virgil-sdk-x)

## Installation

VirgilCrypto is provided as a set of frameworks. These frameworks are distributed via Carthage and CocoaPods.

All frameworks are available for:
- iOS 9.0+
- macOS 10.9+
- tvOS 9.0+
- watchOS 2.0+

### COCOAPODS

[CocoaPods](http://cocoapods.org) is a dependency manager for Cocoa projects. You can install it with the following command:

```bash
$ gem install cocoapods
```

To integrate VirgilCrypto into your Xcode project using CocoaPods, specify it in your *Podfile*:

```bash
target '<Your Target Name>' do
  use_frameworks!

  pod 'VirgilCrypto', '~> 5.5.0'
end
```

Then, run the following command:

```bash
$ pod install
```

### Carthage

[Carthage](https://github.com/Carthage/Carthage) is a decentralized dependency manager that builds your dependencies and provides you with binary frameworks.

You can install Carthage with [Homebrew](http://brew.sh/) using the following command:

```bash
$ brew update
$ brew install carthage
```

To integrate VirgilCrypto into your Xcode project using Carthage, create an empty file with name *Cartfile* in your project's root folder and add following lines to your *Cartfile*

```
github "VirgilSecurity/virgil-crypto-x" ~> 5.5.0
```

#### Linking against prebuilt binaries

To link prebuilt frameworks to your app, run following command:

```bash
$ carthage update
```

This will build each dependency or download a pre-compiled framework from github Releases.

##### Building for iOS/tvOS/watchOS

On your application target's “General” settings tab, in the “Linked Frameworks and Libraries” section, add following frameworks from the *Carthage/Build* folder inside your project's folder:
 - VirgilCrypto
 - VirgilCryptoFoundation
 - VSCCommon
 - VSCFoundation

On your application target's “Build Phases” settings tab, click the “+” icon and choose “New Run Script Phase”. Create a Run Script in which you specify your shell (ex: */bin/sh*), add the following contents to the script area below the shell:

```bash
/usr/local/bin/carthage copy-frameworks
```

and add the paths to the frameworks you want to use under “Input Files”, e.g.:

```
$(SRCROOT)/Carthage/Build/iOS/VirgilCrypto.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilCryptoFoundation.framework
$(SRCROOT)/Carthage/Build/iOS/VSCCommon.framework
$(SRCROOT)/Carthage/Build/iOS/VSCFoundation.framework
```

##### Building for macOS

On your application target's “General” settings tab, in the “Embedded Binaries” section, drag and drop following frameworks from the Carthage/Build folder on disk:
- VirgilCrypto
- VirgilCryptoFoundation
- VSCCommon
- VSCFoundation

Additionally, you'll need to copy debug symbols for debugging and crash reporting on macOS.

On your application target’s “Build Phases” settings tab, click the “+” icon and choose “New Copy Files Phase”.
Click the “Destination” drop-down menu and select “Products Directory”. For each framework, drag and drop the corresponding dSYM file.

## Usage examples

### Generate a key pair

Generate a private key using the default algorithm (EC_X25519):

```swift
import VirgilCrypto

let crypto = try! VirgilCrypto()
let keyPair = try! crypto.generateKeyPair()
```

### Generate and verify a signature

Generate signature and sign data with a private key:

```swift
import VirgilCrypto

let crypto = try! VirgilCrypto()

// prepare a message
let messageToSign = "Hello, Bob!"
let dataToSign = messageToSign.data(using: .utf8)!

// generate a signature
let signature = try! crypto.generateSignature(of: dataToSign, using: senderPrivateKey)
```

Verify a signature with a public key:

```swift
import VirgilCrypto

let crypto = try! VirgilCrypto()

// verify a signature
let verified = try! crypto.verifySignature(signature, of: dataToSign, with: senderPublicKey)
```
### Encrypt and decrypt data

Encrypt data with a public key:

```swift
import VirgilCrypto

let crypto = try! VirgilCrypto()

// prepare a message
let messageToEncrypt = "Hello, Bob!"
let dataToEncrypt = messageToEncrypt.data(using: .utf8)!

// encrypt the message
let encryptedData = try! crypto.encrypt(dataToEncrypt, for: [receiverPublicKey])
```
Decrypt the encrypted data with a Private Key:
```swift
import VirgilCrypto

let crypto = try! VirgilCrypto()

// prepare data to be decrypted
let decryptedData = try! crypto.decrypt(encryptedData, with: receiverPrivateKey)

// decrypt the encrypted data using a private key
let decryptedMessage = String(data: decryptedData, encoding: .utf8)!
```

### Import and export keys

Export keys:

```
import VirgilCrypto

// generate a Key Pair
let crypto = VirgilCrypto()
let keyPair = try! crypto.generateKeyPair()

// export a Private key
let privateKeyData = try! crypto.exportPrivateKey(keyPair.privateKey, password: "YOUR_PASSWORD")
let privateKeyStr = privateKeyData.base64EncodedString()

// export a Public key
let publicKeyData = crypto.exportPublicKey(keyPair.publicKey)
let publicKeyStr = publicKeyData.base64EncodedString()
```

Import keys:

```
import VirgilCrypto

let crypto = VirgilCrypto()

let privateKeyStr = "MIGhMF0GCSqGSIb3DQEFDTBQMC8GCSqGSIb3DQEFDDAiBBBtfBoM7VfmWPlvyHuGWvMSAgIZ6zAKBggqhkiG9w0CCjAdBglghkgBZQMEASoEECwaKJKWFNn3OMVoUXEcmqcEQMZ+WWkmPqzwzJXGFrgS/+bEbr2DvreVgEUiLKrggmXL9ZKugPKG0VhNY0omnCNXDzkXi5dCFp25RLqbbSYsCyw="

let privateKeyData = Data(base64Encoded: privateKeyStr)!

// import a Private key
let privateKey = try! crypto.importPrivateKey(from: privateKeyData, password: "YOUR_PASSWORD")

//-----------------------------------------------------

let publicKeyStr = "MCowBQYDK2VwAyEA9IVUzsQENtRVzhzraTiEZZy7YLq5LDQOXGQG/q0t0kE="

let publicKeyData = Data(base64Encoded: publicKeyStr)!

// import a Public key
let publicKey = try! crypto.importPublicKey(from: publicKeyData)
```

## Docs
- [Crypto Core Library C](https://github.com/VirgilSecurity/virgil-crypto-c)
- [Developer Documentation](https://developer.virgilsecurity.com/docs/)

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you.

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
