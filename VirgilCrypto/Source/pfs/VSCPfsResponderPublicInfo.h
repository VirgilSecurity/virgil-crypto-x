//
//  VSCPfsResponderPublicInfo.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSCPfsPublicKey.h"

/**
 Class that represents Responder Public Info: identity, long-term and one-time public keys.
 */
NS_SWIFT_NAME(PfsResponderPublicInfo)
@interface VSCPfsResponderPublicInfo : NSObject
/**
 Designated initializer.

 @param identityPublicKey identity card public key
 @param longTermPublicKey long-term card public key
 @param oneTimePublicKey one-time card public key
 @return initialized instance
 */
- (instancetype __nullable)initWithIdentityPublicKey:(VSCPfsPublicKey * __nonnull)identityPublicKey longTermPublicKey:(VSCPfsPublicKey * __nonnull)longTermPublicKey oneTimePublicKey:(VSCPfsPublicKey * __nullable)oneTimePublicKey NS_DESIGNATED_INITIALIZER;

/**
 Inherited unavailable initializer.

 @return initialized instance
 */
- (instancetype __nonnull)init NS_UNAVAILABLE;

/**
 Identity card public key
 */
@property (nonatomic, readonly) VSCPfsPublicKey * __nonnull identityPublicKey;

/**
 Long-term card public key
 */
@property (nonatomic, readonly) VSCPfsPublicKey * __nonnull longTermPublicKey;

/**
 One-time card public key
 */
@property (nonatomic, readonly) VSCPfsPublicKey * __nullable oneTimePublicKey;

@end
