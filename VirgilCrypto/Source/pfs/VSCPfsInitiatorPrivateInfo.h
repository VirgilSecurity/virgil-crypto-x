//
//  VSCPfsInitiatorPrivateInfo.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSCPfsPrivateKey.h"

/**
 Class that represents Initiator Private Info: identity and ephemeral private keys.
 */
NS_SWIFT_NAME(PfsInitiatorPrivateInfo)
@interface VSCPfsInitiatorPrivateInfo : NSObject
/**
 Designated initializer

 @param identityPrivateKey identity card private key
 @param ephemeralPrivateKey ephemeral private key
 @return initialized instance
 */
- (instancetype __nullable)initWithIdentityPrivateKey:(VSCPfsPrivateKey * __nonnull)identityPrivateKey ephemeralPrivateKey:(VSCPfsPrivateKey * __nonnull)ephemeralPrivateKey NS_DESIGNATED_INITIALIZER;

/**
 Inherited unavailable initializer.
 
 @return initialized instance
 */
- (instancetype __nonnull)init NS_UNAVAILABLE;

/**
 Identity card private key
 */
@property (nonatomic, readonly) VSCPfsPrivateKey * __nonnull identityPrivateKey;

/**
 Ephemeral private key
 */
@property (nonatomic, readonly) VSCPfsPrivateKey * __nonnull ephemeralPrivateKey;

@end
