//
//  VWCryptor.h
//  VirgilCrypto
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface VCCryptor : NSObject

- (instancetype)init NS_DESIGNATED_INITIALIZER;

/**
 * Encrypt some data using added recepients. Allows to embed info about the recipients so it will be easier to decrypt.
 * @param plainData NSData Data object which needs to be encrypted.
 * @param embedContentInfo NSNumber Boolean flag, if YES then some amount of data with recipients info will be added to the result data.
 * @return NSData Data object with encrypted data.
 */
- (NSData *)encryptData:(NSData *)plainData embedContentInfo:(NSNumber *)embedContentInfo;
/**
 * Decrypt data using key-based decryption.
 * @param encryptedData NSData Data object containing encrypted data which needs to be decrypted.
 * @param publicKeyId NSString with public key identifier used for encryption of the data.
 * @param privateKey NSData Data object containing the private key for decryption (should correspond the public key used for encryption).
 * @param keyPassword NSString Password string used to generate the key pair or nil.
 * @return NSData Data object containing the decrypted data.
 */
- (NSData *)decryptData:(NSData *)encryptedData publicKeyId:(NSString *)publicKeyId privateKey:(NSData *)privateKey keyPassword:(NSString *)keyPassword;
/**
 * Decrypt data using password-based decryption.
 * @param encryptedData NSData Data object containing encrypted data which needs to be decrypted.
 * @param password NSString Password which was used to encrypt the data.
 * @return NSData Data object containing the decrypted data.
 */
- (NSData *)decryptData:(NSData *)encryptedData password:(NSString *)password;

/**
 * Adds given public key as a recipient for encryption. This method should be called before -encryptData:embedContentInfo: in case of using key-based encryption.
 * @param publicKeyId NSString String containing identifier for the public key used for encryption.
 * @param publicKey NSData Data object containing public key which will be used for encryption.
 */
- (void)addKeyRecepient:(NSString *)publicKeyId publicKey:(NSData *)publicKey;
/**
 * Removes a public key with given identifier from the recipients list for encryption.
 * @param publicKeyId NSString String containing identifier for the public key which should be removed.
 */
- (void)removeKeyRecipient:(NSString *)publicKeyId;

/**
 * Adds given password as a recipient for encryption. This method should be called before -encryptData:embedContentInfo: in case of using pasword-based encryption.
 * @param password NSString Password which will be used for encryption.
 */
- (void)addPasswordRecipient:(NSString *)password;
/**
 * Removes given password from the recipients list for encryption.
 * @param password NSString Password which should be removed.
 */
- (void)removePasswordRecipient:(NSString *)password;

/**
 * Removes all recepients which would be used for encryption.
 */
- (void)removeAllRecipients;

/**
 * Allows to get the content info data with information about the encryption recipients in case of parameter embedContentInfo of the -encryptData:embedContentInfo: is set to @NO or nil.
 * @return NSData Data object with content info for encryption data.
 */
- (NSData *)contentInfo;
/**
 * Allows to set the content info data with information about the encryption recipients before any calls to -decryptData: methods in case when data was encrypted with parameter embedContentInfo of the -encryptData:embedContentInfo: was set to @NO or nil.
 * @param NSData Data object with content info for the data decryption.
 */
- (void) setContentInfo:(NSData *) contentInfo;

@end
