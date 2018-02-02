//
//  VSCPfsInitiatorPublicInfo.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSCPfsPublicKey.h"

/**
 Class that represents Initiator Public Info: identity and ephemeral public keys.
 */
NS_SWIFT_NAME(PfsInitiatorPublicInfo)
@interface VSCPfsInitiatorPublicInfo : NSObject
/**
 Designated initializer.

 @param identityPublicKey identity card public key
 @param ephemeralPublicKey ephemeral public key
 @return initialized instance
 */
- (instancetype __nullable)initWithIdentityPublicKey:(VSCPfsPublicKey * __nonnull)identityPublicKey ephemeralPublicKey:(VSCPfsPublicKey * __nonnull)ephemeralPublicKey NS_DESIGNATED_INITIALIZER;

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
 Ephemeral public key
 */
@property (nonatomic, readonly) VSCPfsPublicKey * __nonnull ephemeralPublicKey;

@end
