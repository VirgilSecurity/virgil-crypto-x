//
//  VSCPfsResponderPublicInfo.mm
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSCPfsResponderPublicInfo.h"

@implementation VSCPfsResponderPublicInfo

- (instancetype __nonnull)initWithIdentifier:(NSString * __nonnull)identifier identityPublicKey:(VSCPfsPublicKey * __nonnull)identityPublicKey longTermPublicKey:(VSCPfsPublicKey * __nonnull)longTermPublicKey oneTimePublicKey:(VSCPfsPublicKey * __nonnull)oneTimePublicKey {
    self = [super init];
    if (self) {
        _identifier = [identifier copy];
        _identityPublicKey = identityPublicKey;
        _longTermPublicKey = longTermPublicKey;
        _oneTimePublicKey = oneTimePublicKey;
    }
    
    return self;
}

@end
