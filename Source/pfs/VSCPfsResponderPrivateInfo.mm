//
//  VSCPfsResponderPrivateInfo.mm
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSCPfsResponderPrivateInfo.h"
#import "VSCPfsResponderPrivateInfoPrivate.h"
#import "VSCPfsPrivateKeyPrivate.h"

using virgil::crypto::VirgilByteArray;

@implementation VSCPfsResponderPrivateInfo

- (instancetype)initWithIdentityPrivateKey:(VSCPfsPrivateKey *)identityPrivateKey longTermPrivateKey:(VSCPfsPrivateKey *)longTermPrivateKey oneTimePrivateKey:(VSCPfsPrivateKey *)oneTimePrivateKey {
    self = [super init];
    if (self) {
        try {
            _cppPfsResponderPrivateInfo = new VirgilPFSResponderPrivateInfo(*identityPrivateKey.cppPfsPrivateKey, *longTermPrivateKey.cppPfsPrivateKey, *oneTimePrivateKey.cppPfsPrivateKey);
        }
        catch(...) {
            return nil;
        }
    }
    
    return self;
}

- (VSCPfsPrivateKey *)identityPrivateKey {
    const VirgilByteArray &keyArr = self.cppPfsResponderPrivateInfo->getIdentityPrivateKey().getKey();
    NSData *key = [NSData dataWithBytes:keyArr.data() length:keyArr.size()];
    
    const VirgilByteArray &passwordArr = self.cppPfsResponderPrivateInfo->getIdentityPrivateKey().getPassword();
    NSData *password = [NSData dataWithBytes:passwordArr.data() length:passwordArr.size()];
    
    return [[VSCPfsPrivateKey alloc] initWithKey:key password:password];
}

- (VSCPfsPrivateKey *)longTermPrivateKey {
    const VirgilByteArray &keyArr = self.cppPfsResponderPrivateInfo->getLongTermPrivateKey().getKey();
    NSData *key = [NSData dataWithBytes:keyArr.data() length:keyArr.size()];
    
    const VirgilByteArray &passwordArr = self.cppPfsResponderPrivateInfo->getLongTermPrivateKey().getPassword();
    NSData *password = [NSData dataWithBytes:passwordArr.data() length:passwordArr.size()];
    
    return [[VSCPfsPrivateKey alloc] initWithKey:key password:password];
}

- (VSCPfsPrivateKey *)oneTimePrivateKey {
    const VirgilByteArray &keyArr = self.cppPfsResponderPrivateInfo->getOneTimePrivateKey().getKey();
    NSData *key = [NSData dataWithBytes:keyArr.data() length:keyArr.size()];
    
    const VirgilByteArray &passwordArr = self.cppPfsResponderPrivateInfo->getOneTimePrivateKey().getPassword();
    NSData *password = [NSData dataWithBytes:passwordArr.data() length:passwordArr.size()];
    
    return [[VSCPfsPrivateKey alloc] initWithKey:key password:password];
}

- (void)dealloc {
    delete self.cppPfsResponderPrivateInfo;
}

@end
