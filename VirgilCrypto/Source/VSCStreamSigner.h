//
//  VSCStreamSigner.h
//  VirgilCypto
//
//  Created by Pavel Gorb on 3/2/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSCFoundationCommons.h"

/// Error domain constant for the `VSCStreamSigner` errors.
NS_SWIFT_NAME(kStreamSignerErrorDomain)
extern NSString * __nonnull const kVSCStreamSignerErrorDomain;

/**
 Wrapper for the functionality for composing/verifying signatures of streams.
 
 This wrapper works with `NSInputStream` instead of `NSData` objects.
 */
NS_SWIFT_NAME(StreamSigner)
@interface VSCStreamSigner : NSObject
/**
 Designated initializer

 @param hash Name of the preferred hash function. In case of `nil` default hash function will be used (SHA384). One of the following names should be used: `kVSCHashNameMD5`, `kVSCHashNameSHA256`, `kVSCHashNameSHA384`, `kVSCHashNameSHA512`.
 @return initialized instance.
 */
- (instancetype __nonnull)initWithHash:(NSString * __nullable)hash NS_DESIGNATED_INITIALIZER;

/**
 Generates signature for data provided by the source with given private key.

 @param source Input stream object containing the data which needs to be signed.
 @param privateKey Data object containing user's private key.
 @param keyPassword Password which was used to create key pair object or `nil`.
 @param error `NSError` pointer to get an object in case of error, `nil` - otherwise.
 @return Signature data object.
 */
- (NSData * __nullable)signStreamData:(NSInputStream * __nonnull)source privateKey:(NSData * __nonnull)privateKey keyPassword:(NSString * __nullable)keyPassword error:(NSError * __nullable * __nullable)error;

/**
 Verifies signature.

 @param signature Data object containing a signature.
 @param source Input Stream object containing the data which was used to compose the signature on.
 @param publicKey Data object containing a public key data of a user whose signature needs to be verified.
 @param error `NSError` pointer to get an object in case of error, `nil` - otherwise.
 @return `YES` if signature is verified and can be trusted, `NO` - otherwise.
 */
- (BOOL)verifySignature:(NSData * __nonnull)signature fromStream:(NSInputStream * __nonnull)source publicKey:(NSData * __nonnull)publicKey error:(NSError * __nullable * __nullable)error;

@end
