## Description

Basic low-level framework which allows to perform some most important security operations. This framework is used in the other high-level Virgil frameworks, libraries and applications. Also it might be used as a standalone basic library for any security-concerned applications.

### Creating a new key pair

VCKeyPair instance should be used to generate a pair of keys. It is possible to generate a password-protected private key. In case of password is not given private key will be generated as a plain data. 

```objective-c
//...
#import <VirgilCryptoiOS/VCKeyPair.h>
//...

VCKeyPair *keyPair = [[VCKeyPair alloc] initWithPassword:<# password or nil #>];
NSString *publicKey = [[NSString alloc] initWithData:keyPair.publicKey encoding:NSUTF8StringEncoding];
NSLog(@"%@", publicKey);
NSString *privateKey = [[NSString alloc] initWithData:keyPair.privateKey encoding:NSUTF8StringEncoding];
NSLog(@"%@", privateKey);
```

### Encrypt/decrypt data

VCCryptor objects can perform two ways of encryption/decryption:

- Key-based encryption/decryption.
- Password-based encryption/decryption.

#### Key-based encryption

```objective-c
//...
#import <VirgilCryptoiOS/VCCryptor.h>
//...

// Assuming that we have some initial string message.
NSString *message = @"This is a secret message which should be encrypted.";
// Convert it to the NSData
NSData *toEncrypt = [message dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
// Assuming that we have some key pair generated earlier.
// Create a new VCCryptor instance
VCCryptor *cryptor = [[VCCryptor alloc] init];
// Now we should add a key recepient
[cryptor addKeyRecepient:<# Public Key ID (e.g. UUID) #> publicKey:keyPair.publicKey];
// And now we can easily encrypt the plain data
NSData *encryptedData = [cryptor encryptData:toEncrypt embedContentInfo:@YES];
```

#### Key-based decryption

```objective-c
//...
#import <VirgilCryptoiOS/VCCryptor.h>
//...

// Assuming that we have received some key-based encrypted data.
// Assuming that we have some key pair generated earlier.
// Create a new VCCryptor instance
VCCryptor *decryptor = [[VCCryptor alloc] init];
// Decrypt data
NSData *plainData = [decryptor decryptData:<# NSData to decrypt #> publicKeyId:<# Public Key ID (e.g. UUID) #> privateKey:keyPair.privateKey keyPassword:<# Private key password or nil #>];
// Compose initial message from the plain decrypted data
NSString *initialMessage = [[NSString alloc] initWithData:plainData encoding:NSUTF8StringEncoding];
```

#### Password-based encryption

```objective-c
//...
#import <VirgilCryptoiOS/VCCryptor.h>
//...

// Assuming that we have some initial string message.
NSString *message = @"This is a secret message which should be encrypted with password-based encryption.";
// Convert it to the NSData
NSData *toEncrypt = [message dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
// Assuming that we have some key pair generated earlier.
// Create a new VCCryptor instance
VCCryptor *cryptor = [[VCCryptor alloc] init];
// Now we should add a password recepient
[cryptor addPasswordRecipient:<# Password to encrypt data with #>];
// And now we can encrypt the plain data
NSData *encryptedData = [cryptor encryptData:toEncrypt embedContentInfo:@YES];
```

#### Password-based decryption

```objective-c
//...
#import <VirgilCryptoiOS/VCCryptor.h>
//...

// Assuming that we have received some password-based encrypted data.
// Assuming that we have some key pair generated earlier.
// Create a new VCCryptor instance
VCCryptor *decryptor = [[VCCryptor alloc] init];
// Decrypt data
NSData *plainData = [decryptor decryptData:<# NSData to decrypt #> password:<# Password used to encrypt the data #>];
// Compose initial message from the plain decrypted data
NSString *initialMessage = [[NSString alloc] initWithData:plainData encoding:NSUTF8StringEncoding];
```

### Sign/Verify

VCSigner instances allows to sign some data with a given private key. This is used to make sure that some message/data was really composed and sent by the holder of the private key.

#### Compose a signature

```objective-c
//...
#import <VirgilCryptoiOS/VCSigner.h>
//...

// Assuming that we have some initial string message that we want to sign.
NSString *message = @"This is a secret message which should be signed.";
// Convert it to the NSData
NSData *toSign = [message dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
// Assuming that we have some key pair generated earlier.
// Create a new VCSigner instance
VCSigner *signer = [[VCSigner alloc] init];
// Sign the initial data
NSData *signature = [signer signData:toSign privateKey:keyPair.privateKey keyPassword:<# Private key password or nil #>];
```

#### Verify a signature

To verify some signature it is necessary to have a public key of a user whose signature we want to verify. 

```objective-c
//...
#import <VirgilCryptoiOS/VCSigner.h>
//...

// Assuming that we have the public key of a person whose signature we need to verify
// Assuming that we have a NSData object with signed data.
// Assuming that we have a NSData object with a signature.
// Create a new VCSigner instance
VCSigner *verifier = [[VCSigner alloc] init];
// Sign the initial data
BOOL verified = [verifier verifyData:<# NSData that was signed #> sign:<# NSData with the signature #> publicKey:<# NSData with public key #>];
```

## Requirements

Requires iOS 8.x or greater.

## License

Usage is provided under the [The BSD 3-Clause License](http://opensource.org/licenses/BSD-3-Clause). See LICENSE for the full details.