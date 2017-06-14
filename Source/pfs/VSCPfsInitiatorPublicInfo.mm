//
//  VSCPfsInitiatorPublicInfo.mm
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSCPfsInitiatorPublicInfo.h"
#import "VSCPfsInitiatorPublicInfoPrivate.h"
#import "VSCPfsPublicKeyPrivate.h"

using virgil::crypto::VirgilByteArray;

@implementation VSCPfsInitiatorPublicInfo

- (instancetype)initWithIdentityPublicKey:(VSCPfsPublicKey *)identityPublicKey ephemeralPublicKey:(VSCPfsPublicKey *)ephemeralPublicKey {
    self = [super init];
    if (self) {
        try {
            _cppPfsInitiatorPublicInfo = new VirgilPFSInitiatorPublicInfo(*identityPublicKey.cppPfsPublicKey, *ephemeralPublicKey.cppPfsPublicKey);
        }
        catch(...) {
            return nil;
        }
    }
    
    return self;
}

- (VSCPfsPublicKey *)identityPublicKey {
    const VirgilByteArray &keyArr = self.cppPfsInitiatorPublicInfo->getIdentityPublicKey().getKey();
    NSData *key = [NSData dataWithBytes:keyArr.data() length:keyArr.size()];
    
    return [[VSCPfsPublicKey alloc] initWithKey:key];
}

- (VSCPfsPublicKey *)ephemeralPublicKey {
    const VirgilByteArray &keyArr = self.cppPfsInitiatorPublicInfo->getEphemeralPublicKey().getKey();
    NSData *key = [NSData dataWithBytes:keyArr.data() length:keyArr.size()];
    
    return [[VSCPfsPublicKey alloc] initWithKey:key];
}

- (void)dealloc {
    delete self.cppPfsInitiatorPublicInfo;
}

@end
