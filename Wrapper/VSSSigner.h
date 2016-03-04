//
//  VSSSigner.h
//  VirgilFoundation
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSSFoundationCommons.h"

extern NSString * __nonnull const kVSSSignerErrorDomain;

@interface VSSSigner : NSObject

- (instancetype __nonnull)initWithHash:(NSString * __nullable)hash NS_DESIGNATED_INITIALIZER;

/** 
 * @brief Composes a signature data for given data using a private key.
 * @deprecated Use -signData:privateKey:keyPassword:error: instead.
 *
 * @param data NSData Data object which needs to be signed.
 * @param privateKey NSData Data object containing user's private key.
 * @param keyPassword NSString Password which was used to create key pair object or nil.
 *
 * @return NSData Signature data object. 
 */ 
- (NSData * __nullable)signData:(NSData * __nonnull)data privateKey:(NSData * __nonnull)privateKey keyPassword:(NSString * __nullable)keyPassword;

/**
 * @brief Composes a signature data for given data using a private key.
 *
 * @param data NSData Data object which needs to be signed.
 * @param privateKey NSData Data object containing user's private key.
 * @param keyPassword NSString Password which was used to create key pair object or nil.
 * @param error NSError object if signing process finished with exception.
 *
 * @return NSData Signature data object.
 */
- (NSData * __nullable)signData:(NSData * __nonnull)data privateKey:(NSData * __nonnull)privateKey keyPassword:(NSString * __nullable)keyPassword error:(NSError * __nullable * __nullable)error;

/**
 * @brief Performs verification of a signature for given data using a public key.
 * @deprecated Use verifySignature:data:publicKey:error instead.
 *
 * @param signature NSData Data object containing signature data.
 * @param data NSData Data object which was signed.
 * @param publicKey NSData Data object containing a public key data of a user whose signature needs to be verified.
 *
 * @return BOOL YES if signature is verified and can be trusted, NO - otherwise.
 */
- (BOOL)verifySignature:(NSData * __nonnull)signature data:(NSData * __nonnull)data publicKey:(NSData * __nonnull)publicKey;

/**
 * @brief Performs verification of a signature for given data using a public key.
 *
 * @param signature NSData Data object containing signature data.
 * @param data NSData Data object which was signed.
 * @param publicKey NSData Data object containing a public key data of a user whose signature needs to be verified.
 * @param error NSError object if signing process finished with exception.
 *
 * @return BOOL YES if signature is verified and can be trusted, NO - otherwise.
 */
- (BOOL)verifySignature:(NSData * __nonnull)signature data:(NSData * __nonnull)data publicKey:(NSData * __nonnull)publicKey error:(NSError * __nullable * __nullable)error;

@end
