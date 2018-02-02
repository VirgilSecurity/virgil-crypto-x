//
//  VSCTinyCipher.h
//  VirgilCypto
//
//  Created by Pavel Gorb on 7/12/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>

/// Error domain constant for the `VSCTinyCipher` errors.
extern NSString * __nonnull const kVSCTinyCipherErrorDomain;

/**
 Constants that represents maximum number of bytes in one package.
 */
typedef NS_ENUM(size_t, VSCPackageSize) {
    VSCMinPackageSize = 113,          ///< Min
    VSCShortSMSPackageSize = 120,     ///< Short SMS
    VSCLongSMSPackageSize = 1200      ///< Long SMS
};

/**
 This class aim is to minimize encryption output.
 
 Motivation: Minimize encryption output.
 
 Solution: Throw out crypto agility and transfer minimum public information required for decryption.
 
 Pros:
    - Tiny messages.
 
 Cons:
    - Crypto agility is not included in the message, so encrypted messages should not be stored for a long term.
 
 Details:
    During encryption ciper packs encrypted message and service information to the set of packages,
    which length is limited by maximim package length.
 
 Restrictions:
 Currently supported public/private keys:
    - Curve25519
 
 Minimum package length:
    - 113 bytes
 */
NS_SWIFT_NAME(TinyCipher)
@interface VSCTinyCipher : NSObject
/**
 Maximum number of bytes in one package.
 */
@property (nonatomic, assign, readonly) size_t packageSize;

/**
 Init cipher with given maximum package size.

 @param packageSize Maximum number of bytes in one package
 @return initialized isntance
 */
- (instancetype __nonnull)initWithPackageSize:(VSCPackageSize)packageSize;

/**
 Prepare cipher for the next encryption. Should be used before the next encryption.

 @param error `NSError` pointer to get an object in case of error, `nil` - otherwise.
 @return `YES` if successful, `NO` - otherwise.
 */
- (BOOL)resetWithError:(NSError * __nullable * __nullable)error;

/**
 Encrypts data with given public key.
 @see '[VSCTinyCipher packageAtIndex:error:]'

 @param data Data to be encrypted.
 @param recipientKey Recipient's public key
 @param error `NSError` pointer to get an object in case of error, `nil` - otherwise.
 @return `YES` in case when encryption was successful, `NO` - otherwise.
 */
- (BOOL)encryptData:(NSData * __nonnull)data recipientPublicKey:(NSData * __nonnull)recipientKey error:(NSError * __nullable * __nullable)error;

/**
 Encrypts data with given public key and composes a signature on the data.

 @param data Data to be encrypted
 @param recipientKey Recipient's public key to encrypt data with.
 @param senderKey Sender's private key for signature composition
 @param keyPassword Sender's private key password, might be `nil`.
 @param error `NSError` pointer to get an object in case of error, `nil` - otherwise.
 @return `YES` in case when encryption/signing was successful. `NO` - otherwise
 */
- (BOOL)encryptAndSignData:(NSData * __nonnull)data recipientPublicKey:(NSData * __nonnull)recipientKey senderPrivateKey:(NSData * __nonnull)senderKey senderKeyPassword:(NSString * __nullable)keyPassword error:(NSError * __nullable * __nullable)error;

/**
 Returns total package count available after encryption process.
 Package count is known only when encryption process is completed.
 
 @return total package count available after encryption process.
 */
- (size_t)packageCount;

/**
 Gets the package at the given index.

 @param index Necessary package's index.
 @param error `NSError` pointer to get an object in case of error, `nil` - otherwise.
 @return `NSData` object with requested package or `nil` in case of error.
 */
- (NSData * __nullable)packageAtIndex:(size_t)index error:(NSError * __nullable * __nullable)error;

/**
 Adds a package for the decryption.

 @param package Data object with package content to be accumulated.
 @param error `NSError` pointer to get an object in case of error, `nil` - otherwise.
 @return `YES` if package was accumulated successfully, `NO` - otherwise.
 */
- (BOOL)addPackage:(NSData * __nonnull)package error:(NSError * __nullable * __nullable)error;

/**
 Defines whether all packages was accumulated or not.

 @return `YES` if all packages was successfully accumulated, `NO` - otherwise.
 */
- (BOOL)packagesAccumulated;

/**
 Decrypts accumulated packages.

 @param recipientKey Recipient's private key.
 @param keyPassword Recipient's private key password, might be `nil`.
 @param error `NSError` pointer to get an object in case of error, `nil` - otherwise.
 @return Decrypted data if decryption has been successful or `nil` in case of error.
 */
- (NSData * __nullable)decryptWithRecipientPrivateKey:(NSData * __nonnull)recipientKey recipientKeyPassword:(NSString * __nullable)keyPassword error:(NSError * __nullable * __nullable)error;

/**
 Verifies accumulated packages and then decrypts them.

 @param senderKey Sender's public key for signature verification.
 @param recipientKey Recipient's private key for the data decryption.
 @param keyPassword Recipient's private key password, might be `nil`.
 @param error `NSError` pointer to get an object in case of error, `nil` - otherwise.
 @return Decrypted data if decryption has been successful or `nil` in case of error of decryption or signature verification.
 */
- (NSData * __nullable)verifyAndDecryptWithSenderPublicKey:(NSData * __nonnull)senderKey recipientPrivateKey:(NSData * __nonnull)recipientKey recipientKeyPassword:(NSString * __nullable)keyPassword error:(NSError * __nullable * __nullable)error;

@end
