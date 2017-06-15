//
//  VSCPfsInitiatorPublicInfo.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSCPfsPublicKey.h"

@interface VSCPfsInitiatorPublicInfo : NSObject

- (instancetype __nullable)initWithIdentityPublicKey:(VSCPfsPublicKey * __nonnull)identityPublicKey ephemeralPublicKey:(VSCPfsPublicKey * __nonnull)ephemeralPublicKey;

- (instancetype __nonnull)init NS_UNAVAILABLE;

@property (nonatomic, readonly) NSString * __nonnull identifier;
@property (nonatomic, readonly) VSCPfsPublicKey * __nonnull identityPublicKey;
@property (nonatomic, readonly) VSCPfsPublicKey * __nonnull ephemeralPublicKey;

@end
