//
//  VSSKeyPair.h
//  VirgilFoundation
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface VSSKeyPair : NSObject

/**
 * @brief Initializer generates key pair using 512-bits Brainpool curve without a password.
 */
- (instancetype __nonnull)init;

/**
 * @brief Initializer generates key pair using 512-bits Brainpool curve with given password.
 *
 * @param password NSString password for encrypting the private key of the key pair or nil.
 */
- (instancetype __nonnull)initWithPassword:(NSString * __nullable)password;

/**
 * @brief Generates key pair using 192-bits NIST curve with given password.
 *
 * @param password NSString password for encrypting the private key of the key pair or nil.
 */
+ (VSSKeyPair * __nonnull)ecNist192WithPassword:(NSString * __nullable)password;

/**
 * @brief Generates key pair using 224-bits NIST curve with given password.
 *
 * @param password NSString password for encrypting the private key of the key pair or nil.
 */
+ (VSSKeyPair * __nonnull)ecNist224WithPassword:(NSString * __nullable)password;

/**
 * @brief Generates key pair using 256-bits NIST curve with given password.
 *
 * @param password NSString password for encrypting the private key of the key pair or nil.
 */
+ (VSSKeyPair * __nonnull)ecNist256WithPassword:(NSString * __nullable)password;

/**
 * @brief Generates key pair using 384-bits NIST curve with given password.
 *
 * @param password NSString password for encrypting the private key of the key pair or nil.
 */
+ (VSSKeyPair * __nonnull)ecNist384WithPassword:(NSString * __nullable)password;

/**
 * @brief Generates key pair using 521-bits NIST curve with given password.
 *
 * @param password NSString password for encrypting the private key of the key pair or nil.
 */
+ (VSSKeyPair * __nonnull)ecNist521WithPassword:(NSString * __nullable)password;

/**
 * @brief Generates key pair using 256-bits Brainpool curve with given password.
 *
 * @param password NSString password for encrypting the private key of the key pair or nil.
 */
+ (VSSKeyPair * __nonnull)ecBrainpool256WithPassword:(NSString * __nullable)password;

/**
 * @brief Generates key pair using 384-bits Brainpool curve with given password.
 *
 * @param password NSString password for encrypting the private key of the key pair or nil.
 */
+ (VSSKeyPair * __nonnull)ecBrainpool384WithPassword:(NSString * __nullable)password;

/**
 * @brief Generates key pair using 512-bits Brainpool curve with given password.
 *
 * @param password NSString password for encrypting the private key of the key pair or nil.
 */
+ (VSSKeyPair * __nonnull)ecBrainpool512WithPassword:(NSString * __nullable)password;

/**
 * @brief Generates key pair using 192-bits "Koblitz" curve with given password.
 *
 * @param password NSString password for encrypting the private key of the key pair or nil.
 */
+ (VSSKeyPair * __nonnull)ecKoblitz192WithPassword:(NSString * __nullable)password;

/**
 * @brief Generates key pair using 224-bits "Koblitz" curve with given password.
 *
 * @param password NSString password for encrypting the private key of the key pair or nil.
 */
+ (VSSKeyPair * __nonnull)ecKoblitz224WithPassword:(NSString * __nullable)password;

/**
 * @brief Generates key pair using 256-bits "Koblitz" curve with given password.
 *
 * @param password NSString password for encrypting the private key of the key pair or nil.
 */
+ (VSSKeyPair * __nonnull)ecKoblitz256WithPassword:(NSString * __nullable)password;

/**
 * @brief Generates key pair using RSA 256-bits with given password.
 *
 * @param password NSString password for encrypting the private key of the key pair or nil.
 */
+ (VSSKeyPair * __nonnull)rsa256WithPassword:(NSString * __nullable)password;

/**
 * @brief Generates key pair using RSA 512-bits with given password.
 *
 * @param password NSString password for encrypting the private key of the key pair or nil.
 */
+ (VSSKeyPair * __nonnull)rsa512WithPassword:(NSString * __nullable)password;

/**
 * @brief Generates key pair using RSA 1024-bits with given password.
 *
 * @param password NSString password for encrypting the private key of the key pair or nil.
 */
+ (VSSKeyPair * __nonnull)rsa1024WithPassword:(NSString * __nullable)password;

/**
 * @brief Generates key pair using RSA 2048-bits with given password.
 *
 * @param password NSString password for encrypting the private key of the key pair or nil.
 */
+ (VSSKeyPair * __nonnull)rsa2048WithPassword:(NSString * __nullable)password;

/**
 * @brief Generates key pair using RSA 4096-bits with given password.
 *
 * @param password NSString password for encrypting the private key of the key pair or nil.
 */
+ (VSSKeyPair * __nonnull)rsa4096WithPassword:(NSString * __nullable)password;

/**
 * @brief Generates key pair using curve 25519 with given password.
 *
 * @param password NSString password for encrypting the private key of the key pair or nil.
 */
+ (VSSKeyPair * __nonnull)m255WithPassword:(NSString * __nullable)password;

/**
 * @brief Getter for the public key's data.
 *
 * @return NSData object containing the generated public key data.
 */
- (NSData * __nonnull)publicKey;

/**
 * @brief Getter for the private key's data.
 *
 * @return NSData object containing the generated private key data. In case of non-nil password used in -initWithPassword: initializer private key data will be encrypted using given password.
 */ 
- (NSData * __nonnull)privateKey;

/**
 * @brief Checks if given private key is actually encrypted.
 *
 * @param keyData NSData representing the private key which needs to be checked.
 *
 * @return BOOL YES if the private key is encrypted, NO - otherwise.
 */
+ (BOOL)isEncryptedPrivateKey:(NSData * __nonnull)keyData;

/**
 * @brief Checks if given private key and given password match each other.
 *
 * @param keyData NSData representing the private key.
 * @param password NSString with private key password candidate.
 *
 * @return BOOL YES if the private key and the password match, NO - otherwise.
 */
+ (BOOL)isPrivateKey:(NSData * __nonnull)keyData matchesPassword:(NSString * __nonnull)password;

/**
 * @brief Checks if a public key matches private key, so that they are actual key pair.
 *
 * @param publicKeyData NSData representing a public key.
 * @param privateKeyData NSData representing a private key.
 * @param password NSString private key password or nil.
 *
 * @return BOOL YES in case when given public key matches given private key, NO - otherwise.
 */
+ (BOOL)isPublicKey:(NSData * __nonnull)publicKeyData matchesPrivateKey:(NSData * __nonnull)privateKeyData withPassword:(NSString * __nullable)password;

@end
