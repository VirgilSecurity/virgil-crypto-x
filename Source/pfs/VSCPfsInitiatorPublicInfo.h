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

- (instancetype __nonnull)initWithIdentifier:(NSString * __nonnull)identifier identityPublicKey:(VSCPfsPublicKey * __nonnull)identityPublicKey ephemeralPublicKey:(VSCPfsPublicKey * __nonnull)ephemeralPublicKey;

@property (nonatomic, readonly) NSString * __nonnull identifier;
@property (nonatomic, readonly) VSCPfsPublicKey * __nonnull identityPublicKey;
@property (nonatomic, readonly) VSCPfsPublicKey * __nonnull ephemeralPublicKey;

@end
