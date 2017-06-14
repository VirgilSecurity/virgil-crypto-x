//
//  VSCPfsResponderPrivateInfo.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSCPfsPrivateKey.h"

@interface VSCPfsResponderPrivateInfo : NSObject

- (instancetype __nullable)initWithIdentityPrivateKey:(VSCPfsPrivateKey * __nonnull)identityPrivateKey longTermPrivateKey:(VSCPfsPrivateKey * __nonnull)longTermPrivateKey oneTimePrivateKey:(VSCPfsPrivateKey * __nonnull)oneTimePrivateKey;

@property (nonatomic, readonly) VSCPfsPrivateKey * __nonnull identityPrivateKey;
@property (nonatomic, readonly) VSCPfsPrivateKey * __nonnull longTermPrivateKey;
@property (nonatomic, readonly) VSCPfsPrivateKey * __nonnull oneTimePrivateKey;

@end
