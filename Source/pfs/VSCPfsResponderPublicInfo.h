//
//  VSCPfsResponderPublicInfo.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSCPfsPublicKey.h"

@interface VSCPfsResponderPublicInfo : NSObject

- (instancetype __nullable)initWithIdentityPublicKey:(VSCPfsPublicKey * __nonnull)identityPublicKey longTermPublicKey:(VSCPfsPublicKey * __nonnull)longTermPublicKey oneTimePublicKey:(VSCPfsPublicKey * __nonnull)oneTimePublicKey;

@property (nonatomic, readonly) VSCPfsPublicKey * __nonnull identityPublicKey;
@property (nonatomic, readonly) VSCPfsPublicKey * __nonnull longTermPublicKey;
@property (nonatomic, readonly) VSCPfsPublicKey * __nonnull oneTimePublicKey;

@end
