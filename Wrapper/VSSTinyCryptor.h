//
//  VSSTinyCryptor.h
//  VirgilCypto
//
//  Created by Pavel Gorb on 7/12/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>

/**
 * Error domain constant for the `VSSPBKDF` errors.
 */
extern NSString * __nonnull const kVSSTinyCryptorErrorDomain;

/**
 * @brief Constants that represents maximum number of bytes in one package.
 * @note Text representation is 4/3 bigger, i.e 120 * 4/3 = 160 - for short sms.
 */
typedef NS_ENUM(size_t, VSSPackageSize) {
    VSSMinPackageSize = 113,          ///< Min
    VSSShortSMSPackageSize = 120,     ///< Short SMS
    VSSLongSMSPackageSize = 1200      ///< Long SMS
};

/**
 * This class aim is to minimize encryption output.
 *
 * Motivation: If encrypted data is transmitted over GSM module, it very important that encryption output was as small as possible.
 *
 * Solution: Throw out crypto agility and transfer minimum public information required for decryption.
 *
 * Pros:
 * - Tiny messages.
 *
 * Cons:
 * - Crypto agility is not included in the message, so encrypted messages should not be stored for a long term.
 *
 * Details:
 * During encryption ciper packs encrypted message and service information to the set of packages,
 * which length is limited by maximim package length.
 *
 * Restrictions:
 * Currently supported public/private keys:
 * - Curve25519
 *
 * Minimum package length:
 * - 113 bytes
 */
@interface VSSTinyCryptor : NSObject

/**
 *  Maximum number of bytes in one package.
 */
@property (nonatomic, assign, readonly) size_t packageSize;

///-------------------------
/// @name Lifecycle
///-------------------------

/**
 * Init cipher with given maximum package size.
 *
 * @param packageSize Maximum number of bytes in one package
 *
 * @return Instance of the `TinyCryptor`
 */
- (instancetype __nonnull)initWithPackageSize:(VSSPackageSize)packageSize;

/**
 * Prepare cryptor for the next encryption.
 *
 * @param error NSError pointer to get an object in case of error, `nil` - otherwise.
 *
 * **Note:** should be used before the next encryption.
 */
- (BOOL)resetWithError:(NSError * __nullable * __nullable)error;

///---------------------------
/// @name Encryption
///---------------------------

/**
 * Encrypts data with given public key
 *
 * @param data Data to be encrypted.
 * @param recipientKey Recipient's public key
 * @param error NSError pointer to get an object in case of error, `nil` - otherwise.
 * 
 * @return `YES` in case when encryption was successful, `NO` - otherwise.
 *
 * @see '[VSSTinyCryptor packageAtIndex:error:]'
 *
 */
- (BOOL)encryptData:(NSData * __nonnull)data recipientPublicKey:(NSData * __nonnull)recipientKey error:(NSError * __nullable * __nullable)error;

/**
 * Encrypts data with given public key and composes a signature on the data.
 *
 * @param data Data to be encrypted
 * @param recipientKey Recipient's public key to encrypt data with.
 * @param senderKey Sender's private key for signature composition
 * @param keyPassword Sender's private key password, might be `nil`.
 * @param error NSError pointer to get an object in case of error, `nil` - otherwise.
 * 
 * @return `YES` in case when encryption/signing was successful. `NO` - otherwise
 */
- (BOOL)encryptAndSignData:(NSData * __nonnull)data recipientPublicKey:(NSData * __nonnull)recipientKey senderPrivateKey:(NSData * __nonnull)senderKey senderKeyPassword:(NSString * __nullable)keyPassword error:(NSError * __nullable * __nullable)error;

/**
 * Returns total package count available after encryption process.
 *
 * **Note:** Package count is known only when encryption process is completed.
 *
 */
- (size_t)packageCount;

/**
 * Gets the package at the given index.
 *
 * @param index Necessary package's index.
 * @param error NSError pointer to get an object in case of error, `nil` - otherwise.
 * 
 * @return NSData object with requested package or `nil` in case of error.
 *
 * **Note:** Package count is known only when encryption process is completed.
 */
- (NSData * __nullable)packageAtIndex:(size_t)index error:(NSError * __nullable * __nullable)error;

///---------------------------
/// @name Decryption
///---------------------------

/**
 * Adds a package for the decryption.
 *
 * Packages added using this function become accumulated for later calls to 
 * - `[VSSTinyCryptor decryptWithRecipientPrivateKey:recipientKeyPassword:error:]` or
 * - `[VSSTinyCryptor verifyAndDecryptWithSenderPublicKey:recipientPrivateKey:recipientKeyPassword:error:]`
 *
 * @param package Data object with package content to be accumulated.
 * @param error NSError pointer to get an object in case of error, `nil` - otherwise.
 *
 * @return `YES` if package was accumulated successfully, `NO` - otherwise.
 */
- (BOOL)addPackage:(NSData * __nonnull)package error:(NSError * __nullable * __nullable)error;

/**
 * Defines whether all packages was accumulated or not.
 *
 * @return `YES` if all packages was successfully accumulated, `NO` - otherwise.
 *
 */
- (BOOL)packagesAccumulated;

/**
 * Decrypts accumulated packages.
 *
 * @param recipientKey Recipient's private key.
 * @param keyPassword Recipient's private key password, might be `nil`.
 * @param error NSError pointer to get an object in case of error, `nil` - otherwise.
 *
 * @return Decrypted data if decryption has been successful or `nil` in case of error.
 */
- (NSData * __nullable)decryptWithRecipientPrivateKey:(NSData * __nonnull)recipientKey recipientKeyPassword:(NSString * __nullable)keyPassword error:(NSError * __nullable * __nullable)error;

/**
 * Verifies accumulated packages and then decrypts them.
 *
 * @param senderKey Sender's public key for signature verification.
 * @param recipientKey Recipient's private key for the data decryption.
 * @param keyPassword Recipient's private key password, might be `nil`.
 * @param error NSError pointer to get an object in case of error, `nil` - otherwise.
 *
 * @return Decrypted data if decryption has been successful or `nil` in case of error of decryption or signature verification.
 */
- (NSData * __nullable)verifyAndDecryptWithSenderPublicKey:(NSData * __nonnull)senderKey recipientPrivateKey:(NSData * __nonnull)recipientKey recipientKeyPassword:(NSString * __nullable)keyPassword error:(NSError * __nullable * __nullable)error;

@end
