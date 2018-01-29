//
//  VSCPfsInitiatorPrivateInfo.mm
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSCPfsInitiatorPrivateInfo.h"
#import "VSCPfsInitiatorPrivateInfoPrivate.h"
#import "VSCPfsPrivateKeyPrivate.h"

using virgil::crypto::VirgilByteArray;

@implementation VSCPfsInitiatorPrivateInfo

- (instancetype)initWithIdentityPrivateKey:(VSCPfsPrivateKey *)identityPrivateKey ephemeralPrivateKey:(VSCPfsPrivateKey *)ephemeralPrivateKey {
    self = [super init];
    if (self) {
        try {
            _cppPfsInitiatorPrivateInfo = new VirgilPFSInitiatorPrivateInfo(*identityPrivateKey.cppPfsPrivateKey, *ephemeralPrivateKey.cppPfsPrivateKey);
        }
        catch(...) {
            return nil;
        }
    }
    
    return self;
}

- (VSCPfsPrivateKey *)identityPrivateKey {
    const VirgilByteArray &keyArr = self.cppPfsInitiatorPrivateInfo->getIdentityPrivateKey().getKey();
    NSData *key = [NSData dataWithBytes:keyArr.data() length:keyArr.size()];
    
    const VirgilByteArray &passwordArr = self.cppPfsInitiatorPrivateInfo->getIdentityPrivateKey().getPassword();
    NSData *password = [NSData dataWithBytes:passwordArr.data() length:passwordArr.size()];
    
    return [[VSCPfsPrivateKey alloc] initWithKey:key password:password];
}

- (VSCPfsPrivateKey *)ephemeralPrivateKey {
    const VirgilByteArray &keyArr = self.cppPfsInitiatorPrivateInfo->getEphemeralPrivateKey().getKey();
    NSData *key = [NSData dataWithBytes:keyArr.data() length:keyArr.size()];
    
    const VirgilByteArray &passwordArr = self.cppPfsInitiatorPrivateInfo->getEphemeralPrivateKey().getPassword();
    NSData *password = [NSData dataWithBytes:passwordArr.data() length:passwordArr.size()];
    
    return [[VSCPfsPrivateKey alloc] initWithKey:key password:password];
}

- (void)dealloc {
    delete self.cppPfsInitiatorPrivateInfo;
}

@end
