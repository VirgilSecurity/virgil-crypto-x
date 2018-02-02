//
//  VSCPfsResponderPrivateInfo.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSCPfsPrivateKey.h"

/**
 Class that represents Responder Private Info: identity, long-term and one-time private keys.
 */
NS_SWIFT_NAME(PfsResponderPrivateInfo)
@interface VSCPfsResponderPrivateInfo : NSObject
/**
 Designated initializer.

 @param identityPrivateKey identity card private key
 @param longTermPrivateKey long-term card private key
 @param oneTimePrivateKey one-time card private key
 @return initialized instance
 */
- (instancetype __nullable)initWithIdentityPrivateKey:(VSCPfsPrivateKey * __nonnull)identityPrivateKey longTermPrivateKey:(VSCPfsPrivateKey * __nonnull)longTermPrivateKey oneTimePrivateKey:(VSCPfsPrivateKey * __nullable)oneTimePrivateKey NS_DESIGNATED_INITIALIZER;

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
 Long-term card private key
 */
@property (nonatomic, readonly) VSCPfsPrivateKey * __nonnull longTermPrivateKey;

/**
 One-time card private key
 */
@property (nonatomic, readonly) VSCPfsPrivateKey * __nullable oneTimePrivateKey;

@end
