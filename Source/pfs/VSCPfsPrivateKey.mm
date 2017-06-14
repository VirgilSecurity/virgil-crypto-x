//
//  VSCPfsPrivateKey.mm
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSCPfsPrivateKey.h"
#import "VSCByteArrayUtils_Private.h"

#import <virgil/crypto/pfs/VirgilPFSPrivateKey.h>

using virgil::crypto::pfs::VirgilPFSPrivateKey;
using virgil::crypto::VirgilByteArray;

@interface VSCPfsPrivateKey ()

@property (nonatomic, assign, readonly) VirgilPFSPrivateKey * __nonnull cppPfsPrivateKey;

@end

@implementation VSCPfsPrivateKey

- (instancetype)initWithKey:(NSData *)key password:(NSData *)password {
    self = [super init];
    if (self) {
        try {
            const VirgilByteArray &keyArr = [VSCByteArrayUtils convertVirgilByteArrayFromData:key];
            const VirgilByteArray &passArr = [VSCByteArrayUtils convertVirgilByteArrayFromData:password];
            _cppPfsPrivateKey = new VirgilPFSPrivateKey(keyArr, passArr);
        }
        catch(...) {
            return nil;
        }
    }
    
    return self;
}

- (BOOL)isEmpty {
    return self.cppPfsPrivateKey->isEmpty();
}

- (NSData *)key {
    const VirgilByteArray &keyArr = self.cppPfsPrivateKey->getKey();
    return [NSData dataWithBytes:keyArr.data() length:keyArr.size()];
}

- (NSData *)password {
    const VirgilByteArray &passArr = self.cppPfsPrivateKey->getPassword();
    return [NSData dataWithBytes:passArr.data() length:passArr.size()];
}

- (void)dealloc {
    delete self.cppPfsPrivateKey;
}

@end
