//
//  VSCPfsInitiatorPrivateInfo.mm
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSCPfsInitiatorPrivateInfo.h"

@implementation VSCPfsInitiatorPrivateInfo

- (instancetype)initWithIdentifier:(NSString *)identifier identityPrivateKey:(VSCPfsPrivateKey *)identityPrivateKey ephemeralPrivateKey:(VSCPfsPrivateKey *)ephemeralPrivateKey {
    self = [super init];
    if (self) {
        _identifier = [identifier copy];
        _identityPrivateKey = identityPrivateKey;
        _ephemeralPrivateKey = ephemeralPrivateKey;
    }
    
    return self;
}

@end
