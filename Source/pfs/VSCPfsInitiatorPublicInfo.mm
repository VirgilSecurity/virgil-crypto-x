//
//  VSCPfsInitiatorPublicInfo.mm
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSCPfsInitiatorPublicInfo.h"

@implementation VSCPfsInitiatorPublicInfo

- (instancetype)initWithIdentifier:(NSString *)identifier identityPublicKey:(VSCPfsPublicKey *)identityPublicKey ephemeralPublicKey:(VSCPfsPublicKey *)ephemeralPublicKey {
    self = [super init];
    if (self) {
        _identifier = [identifier copy];
        _identityPublicKey = [identityPublicKey copy];
        _ephemeralPublicKey = [ephemeralPublicKey copy];
    }
    
    return self;
}

@end
