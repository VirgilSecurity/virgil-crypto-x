//
//  VSCKeyPair.h
//  VirgilFoundation
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

/** 
 * Error domain constant for the `VSSKeyPair` errors.
 */
extern NSString * __nonnull const kVSSKeyPairErrorDomain;

typedef NS_ENUM(NSInteger, VSCKeyType) {
    VSCKeyTypeRSA_256, ///< RSA 1024 bit (not recommended)
    VSCKeyTypeRSA_512, ///< RSA 1024 bit (not recommended)
    VSCKeyTypeRSA_1024, ///< RSA 1024 bit (not recommended)
    VSCKeyTypeRSA_2048, ///< RSA 2048 bit (not recommended)
    VSCKeyTypeRSA_3072, ///< RSA 3072 bit
    VSCKeyTypeRSA_4096, ///< RSA 4096 bit
    VSCKeyTypeRSA_8192, ///< RSA 8192 bit
    VSCKeyTypeEC_SECP192R1, ///< 192-bits NIST curve
    VSCKeyTypeEC_SECP224R1, ///< 224-bits NIST curve
    VSCKeyTypeEC_SECP256R1, ///< 256-bits NIST curve
    VSCKeyTypeEC_SECP384R1, ///< 384-bits NIST curve
    VSCKeyTypeEC_SECP521R1, ///< 521-bits NIST curve
    VSCKeyTypeEC_BP256R1, ///< 256-bits Brainpool curve
    VSCKeyTypeEC_BP384R1, ///< 384-bits Brainpool curve
    VSCKeyTypeEC_BP512R1, ///< 512-bits Brainpool curve
    VSCKeyTypeEC_SECP192K1, ///< 192-bits "Koblitz" curve
    VSCKeyTypeEC_SECP224K1, ///< 224-bits "Koblitz" curve
    VSCKeyTypeEC_SECP256K1, ///< 256-bits "Koblitz" curve
    VSCKeyTypeEC_CURVE25519, ///< Curve25519 as ECP deprecated format
    VSCKeyTypeFAST_EC_X25519,  ///< Curve25519
    VSCKeyTypeFAST_EC_ED25519, ///< Ed25519
};

/** 
 * Class for generating asymmetric key pairs using a number of alghorithms. 
 */
@interface VSCKeyPair : NSObject

///---------------------------
/// @name Lifecycle
///---------------------------

/** <Need to Update>
 * Generates a new key pair using curve 25519 without a password. 
 */
- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithKeyPairType:(VSCKeyType)keyPairType password:(NSString * __nullable)password;


///---------------------------
/// @name Obtaining the key data
///---------------------------

/** 
 * Getter for the public key's data.
 *
 * @return Data object containing the generated public key data.
 */
- (NSData * __nonnull)publicKey;

/** 
 * Getter for the private key's data.
 *
 * @return Data object containing the generated private key data. 
 * In case of not `nil` password used in `initWithPassword:` initializer,
 * private key data will be encrypted using given password.
 */ 
- (NSData * __nonnull)privateKey;

///---------------------------
/// @name Utility
///---------------------------

+ (NSData * __nullable)extractPublicKeyWithPrivateKey:(NSData * __nonnull)privateKey privateKeyPassword:(NSString * __nonnull)password ;

+ (NSData * __nullable)encryptPrivateKey:(NSData * __nonnull)privateKey privateKeyPassword:(NSString * __nonnull)password;
+ (NSData * __nullable)decryptPrivateKey:(NSData * __nonnull)privateKey privateKeyPassword:(NSString * __nonnull)password;

/** Checks if given private key is actually encrypted.
 *
 * @param keyData Data representing the private key which needs to be checked.
 *
 * @return `YES` if the private key is encrypted, `NO` - otherwise.
 */
+ (BOOL)isEncryptedPrivateKey:(NSData * __nonnull)keyData;

/** Checks if given private key and given password match each other.
 *
 * @param keyData Data representing the private key.
 * @param password String with private key password candidate.
 *
 * @return `YES` if the private key and the password match, `NO` - otherwise.
 */
+ (BOOL)isPrivateKey:(NSData * __nonnull)keyData matchesPassword:(NSString * __nonnull)password;

/** Checks if a public key matches private key, so that they are actual key pair.
 *
 * @param publicKeyData Data representing a public key.
 * @param privateKeyData Data representing a private key.
 * @param password Private key password or nil.
 *
 * @return `YES` in case when given public key matches given private key, `NO` - otherwise.
 */
+ (BOOL)isPublicKey:(NSData * __nonnull)publicKeyData matchesPrivateKey:(NSData * __nonnull)privateKeyData withPassword:(NSString * __nullable)password;

/** Changes password for the given private key by re-encrypting given private key with a new password.
 *
 * @param password Current password for the private key.
 * @param newPassword Password which should be used for the private key protection further.
 * @param keyData Data object containing the private key.
 * @param error Pointer to `NSError` object in case of error, `nil` - otherwise.
 *
 * @return Data object containing the private key that is encrypted with the new password or `nil` if error has happened.
 */
+ (NSData * __nullable)resetPassword:(NSString * __nonnull)password toPassword:(NSString * __nonnull)newPassword forPrivateKey:(NSData * __nonnull)keyData error:(NSError * __nullable * __nullable)error;

+ (NSData * __nullable)publicKeyToPEM:(NSData * __nonnull)publicKey;
+ (NSData * __nullable)publicKeyToDER:(NSData * __nonnull)publicKey;

+ (NSData * __nullable)privateKeyToPEM:(NSData *__nonnull)privateKey;
+ (NSData * __nullable)privateKeyToDER:(NSData *__nonnull)privateKey;

+ (NSData * __nullable)privateKeyToPEM:(NSData *__nonnull)privateKey privateKeyPassword:(NSString * __nullable)password;
+ (NSData * __nullable)privateKeyToDER:(NSData *__nonnull)privateKey privateKeyPassword:(NSString * __nullable)password;

@end
