//
//  VSSCryptor.h
//  VirgilFoundation
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSSBaseCryptor.h"

extern NSString * __nonnull const kVSSCryptorErrorDomain;

@interface VSSCryptor : VSSBaseCryptor

/**
 * @brief Encrypt some data using added recepients. Allows to embed info about the recipients so it will be easier to decrypt.
 * @deprecated Use -encryptData:embedContentInfo:error: instead.
 *
 * @param plainData NSData Data object which needs to be encrypted.
 * @param embedContentInfo NSNumber Boolean flag, if YES then some amount of data with recipients info will be added to the result data.
 *
 * @return NSData Data object with encrypted data or nil in case of error.
 */
- (NSData * __nullable)encryptData:(NSData * __nonnull)plainData embedContentInfo:(NSNumber * __nonnull)embedContentInfo;

/**
 * @brief Encrypt some data using added recepients. Allows to embed info about the recipients so it will be easier to decrypt.
 *
 * @param plainData NSData Data object which needs to be encrypted.
 * @param embedContentInfo NSNumber Boolean flag, if YES then some amount of data with recipients info will be added to the result data.
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 *
 * @return NSData Data object with encrypted data or nil in case of error.
 */
- (NSData * __nullable)encryptData:(NSData * __nonnull)plainData embedContentInfo:(BOOL)embedContentInfo error:(NSError * __nullable * __nullable)error;
/**
 * @brief Decrypt data using key-based decryption.
 * @deprecated Use -decryptData:recipientId:privateKey:keyPassword:error: instead.
 *
 * @param encryptedData NSData Data object containing encrypted data which needs to be decrypted.
 * @param publicKeyId NSString with public key identifier used for encryption of the data.
 * @param privateKey NSData Data object containing the private key for decryption (should correspond the public key used for encryption).
 * @param keyPassword NSString Password string used to generate the key pair or nil.
 *
 * @return NSData Data object containing the decrypted data or nil in case of error.
 */
- (NSData * __nullable)decryptData:(NSData * __nonnull)encryptedData recipientId:(NSString * __nonnull)recipientId privateKey:(NSData * __nonnull)privateKey keyPassword:(NSString * __nullable)keyPassword;

/**
 * @brief Decrypt data using key-based decryption.
 *
 * @param encryptedData NSData Data object containing encrypted data which needs to be decrypted.
 * @param publicKeyId NSString with public key identifier used for encryption of the data.
 * @param privateKey NSData Data object containing the private key for decryption (should correspond the public key used for encryption).
 * @param keyPassword NSString Password string used to generate the key pair or nil.
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 *
 * @return NSData Data object containing the decrypted data or nil in case of error.
 */
- (NSData * __nullable)decryptData:(NSData * __nonnull)encryptedData recipientId:(NSString * __nonnull)recipientId privateKey:(NSData * __nonnull)privateKey keyPassword:(NSString * __nullable)keyPassword error:(NSError *__nullable * __nullable)error;

/**
 * @brief Decrypt data using password-based decryption.
 * @deprecated Use -decryptData:password:error: instead
 *
 * @param encryptedData NSData Data object containing encrypted data which needs to be decrypted.
 * @param password NSString Password which was used to encrypt the data.
 *
 * @return NSData Data object containing the decrypted data or nil in case of error.
 */
- (NSData * __nullable)decryptData:(NSData * __nonnull)encryptedData password:(NSString * __nonnull)password;

/**
 * @brief Decrypt data using password-based decryption.
 *
 * @param encryptedData NSData Data object containing encrypted data which needs to be decrypted.
 * @param password NSString Password which was used to encrypt the data.
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 *
 * @return NSData Data object containing the decrypted data or nil in case of error.
 */
- (NSData * __nullable)decryptData:(NSData * __nonnull)encryptedData password:(NSString * __nonnull)password error:(NSError * __nullable * __nullable)error;

@end
