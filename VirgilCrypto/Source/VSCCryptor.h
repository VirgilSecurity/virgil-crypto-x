//
//  VSCCryptor.h
//  VirgilFoundation
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSCBaseCryptor.h"

/**
 * Error domain constant for the VSCCryptor errors.
 */
extern NSString * __nonnull const kVSCCryptorErrorDomain;

/**
 * Class for encryption/decryption functionality.
 */
@interface VSCCryptor : VSCBaseCryptor

///---------------------------
/// @name Encryption
///---------------------------

/** 
 * Encrypts the given data using added recepients. Allows to embed info about the recipients so it will be easier to setup decryption.
 *
 * @param plainData Data object which needs to be encrypted.
 * @param embedContentInfo `YES` in case when some amount of data with recipients info will be added to the result data.
 * @param error `NSError` pointer to get an object in case of error, `nil` - otherwise.
 *
 * @return Data object with encrypted data or `nil` in case of error.
 */
- (NSData * __nullable)encryptData:(NSData * __nonnull)plainData embedContentInfo:(BOOL)embedContentInfo error:(NSError * __nullable * __nullable)error;

///---------------------------
/// @name Decryption
///---------------------------

/** 
 * Decrypts data using key-based decryption.
 *
 * @param encryptedData Data object containing encrypted data which needs to be decrypted.
 * @param recipientId Recipient identifier used for encryption of the data.
 * @param privateKey Data object containing the private key for decryption (should correspond the public key used for encryption).
 * @param keyPassword Password string used to generate the key pair or `nil`.
 * @param error `NSError` pointer to get an object in case of error, `nil` - otherwise.
 *
 * @return Data object containing the decrypted data or `nil` in case of error.
 */
- (NSData * __nullable)decryptData:(NSData * __nonnull)encryptedData recipientId:(NSData * __nonnull)recipientId privateKey:(NSData * __nonnull)privateKey keyPassword:(NSString * __nullable)keyPassword error:(NSError *__nullable * __nullable)error;

/** 
 * Decrypts data using password-based decryption.
 *
 * @param encryptedData Data object containing encrypted data which needs to be decrypted.
 * @param password Password which was used to encrypt the data.
 * @param error NSError pointer to get an object in case of error, `nil` - otherwise.
 *
 * @return Data object containing the decrypted data or `nil` in case of error.
 */
- (NSData * __nullable)decryptData:(NSData * __nonnull)encryptedData password:(NSString * __nonnull)password error:(NSError * __nullable * __nullable)error;

@end
