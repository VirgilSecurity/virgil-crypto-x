//
//  VCSigner.h
//  VirgilCrypto
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

extern NSString* const kHashNameMD5;
extern NSString* const kHashNameSHA256;
extern NSString* const kHashNameSHA384;
extern NSString* const kHashNameSHA512;

@interface VCSigner : NSObject

- (instancetype)init;
- (instancetype)initWithHash:(NSString *)hash NS_DESIGNATED_INITIALIZER;

/** 
 * Composes a signature data for given data using a private key.
 * @param data NSData Data object which needs to be signed.
 * @param privateKey NSData Data object containing user's private key.
 * @param keyPassword NSString Password which was used to create key pair object or nil.
 * @return NSData Signature data object. 
 */ 
- (NSData *)signData:(NSData *)data privateKey:(NSData *)privateKey keyPassword:(NSString *)keyPassword;
/** 
 * Performs verification of a signature for given data using a public key.
 * @param signature NSData Data object containing signature data.
 * @param data NSData Data object which was signed.
 * @param publicKey NSData Data object containing a public key data of a user whose signature needs to be verified.
 * @return BOOL If YES then signature is verified and can be trusted. No - otherwise. 
 */
- (BOOL)verifySignature:(NSData *)signature data:(NSData *)data publicKey:(NSData *)publicKey;

@end
