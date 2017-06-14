//
//  VSCPfsInitiatorPrivateInfo.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSCPfsPrivateKey.h"

@interface VSCPfsInitiatorPrivateInfo : NSObject

- (instancetype __nonnull)initWithIdentifier:(NSString * __nonnull)identifier identityPrivateKey:(VSCPfsPrivateKey * __nonnull)identityPrivateKey ephemeralPrivateKey:(VSCPfsPrivateKey * __nonnull)ephemeralPrivateKey;

@property (nonatomic, readonly) NSString * __nonnull identifier;
@property (nonatomic, readonly) VSCPfsPrivateKey * __nonnull identityPrivateKey;
@property (nonatomic, readonly) VSCPfsPrivateKey * __nonnull ephemeralPrivateKey;

@end
