//
//  VSCPfsResponderPrivateInfo.mm
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSCPfsResponderPrivateInfo.h"

@implementation VSCPfsResponderPrivateInfo

- (instancetype)initWithIdentifier:(NSString *)identifier identityPrivateKey:(VSCPfsPrivateKey *)identityPrivateKey longTermPrivateKey:(VSCPfsPrivateKey *)longTermPrivateKey oneTimePrivateKey:(VSCPfsPrivateKey *)oneTimePrivateKey {
    self = [super init];
    if (self) {
        _identifier = [identifier copy];
        _identityPrivateKey = identityPrivateKey;
        _longTermPrivateKey = longTermPrivateKey;
        _oneTimePrivateKey = oneTimePrivateKey;
    }
    
    return self;
}

@end
