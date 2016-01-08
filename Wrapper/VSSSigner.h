//
//  VSSSigner.h
//  VirgilFoundation
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

extern NSString * __nonnull const kHashNameMD5;
extern NSString * __nonnull const kHashNameSHA256;
extern NSString * __nonnull const kHashNameSHA384;
extern NSString * __nonnull const kHashNameSHA512;

@interface VSSSigner : NSObject

- (instancetype __nonnull)init;
- (instancetype __nonnull)initWithHash:(NSString * __nullable)hash NS_DESIGNATED_INITIALIZER;

/** 
 * Composes a signature data for given data using a private key.
 * @param data NSData Data object which needs to be signed.
 * @param privateKey NSData Data object containing user's private key.
 * @param keyPassword NSString Password which was used to create key pair object or nil.
 * @return NSData Signature data object. 
 */ 
- (NSData * __nullable)signData:(NSData * __nonnull)data privateKey:(NSData * __nonnull)privateKey keyPassword:(NSString * __nullable)keyPassword;
/** 
 * Performs verification of a signature for given data using a public key.
 * @param signature NSData Data object containing signature data.
 * @param data NSData Data object which was signed.
 * @param publicKey NSData Data object containing a public key data of a user whose signature needs to be verified.
 * @return BOOL If YES then signature is verified and can be trusted. No - otherwise. 
 */
- (BOOL)verifySignature:(NSData * __nonnull)signature data:(NSData * __nonnull)data publicKey:(NSData * __nonnull)publicKey;

@end
