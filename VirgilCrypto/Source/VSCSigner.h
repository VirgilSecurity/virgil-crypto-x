//
//  VSCSigner.h
//  VirgilFoundation
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSCFoundationCommons.h"

/// Error domain constant for the `VSCSigner` errors.
NS_SWIFT_NAME(kSignerErrorDomain)
extern NSString * __nonnull const kVSCSignerErrorDomain;

/** 
 * Wrapper for the functionality of composing/verifying signatures.
 */
NS_SWIFT_NAME(Signer)
@interface VSCSigner : NSObject
/**
 Designated constructor.

 @param hash NSString name of the preferred hash function. In case of `nil` default hash function will be used (SHA384). One of the following names should be used: `kVSCHashNameMD5`, `kVSCHashNameSHA256`, `kVSCHashNameSHA384`, `kVSCHashNameSHA512`.
 @return initialized instance
 */
- (instancetype __nonnull)initWithHash:(NSString * __nullable)hash NS_DESIGNATED_INITIALIZER;

/**
 Generates signature data for given data using a private key.

 @param data Data object which needs to be signed.
 @param privateKey Data object containing user's private key.
 @param keyPassword Password which was used to create key pair object or `nil`.
 @param error `NSError` pointer to get an object in case of error, `nil` - otherwise.
 @return Signature data object.
 */
- (NSData * __nullable)signData:(NSData * __nonnull)data privateKey:(NSData * __nonnull)privateKey keyPassword:(NSString * __nullable)keyPassword error:(NSError * __nullable * __nullable)error;

/**
 Performs verification of a signature for given data using a public key.

 @param signature Data object containing a signature data.
 @param data Data object which was used to compose the signature on.
 @param publicKey Data object containing a public key data of the user whose signature needs to be verified.
 @param error `NSError` pointer to get an object in case of error, `nil` - otherwise.
 @return `YES` if signature is verified and can be trusted, `NO` - otherwise.
 */
- (BOOL)verifySignature:(NSData * __nonnull)signature data:(NSData * __nonnull)data publicKey:(NSData * __nonnull)publicKey error:(NSError * __nullable * __nullable)error;

@end
