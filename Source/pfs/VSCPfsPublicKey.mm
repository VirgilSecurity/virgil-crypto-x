//
//  VSCPfsPublicKey.mm
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSCPfsPublicKey.h"
#import "VSCByteArrayUtils_Private.h"

#import <virgil/crypto/pfs/VirgilPFSPublicKey.h>

using virgil::crypto::pfs::VirgilPFSPublicKey;
using virgil::crypto::VirgilByteArray;

@interface VSCPfsPublicKey ()

@property (nonatomic, assign, readonly) VirgilPFSPublicKey * __nonnull cppPfsPublicKey;

@end

@implementation VSCPfsPublicKey

- (instancetype)initWithKey:(NSData *)key {
    self = [super init];
    if (self) {
        try {
            const VirgilByteArray &keyArr = [VSCByteArrayUtils convertVirgilByteArrayFromData:key];
            _cppPfsPublicKey = new VirgilPFSPublicKey(keyArr);
        }
        catch(...) {
            return nil;
        }
    }
    
    return self;
}

- (BOOL)isEmpty {
    return self.cppPfsPublicKey->isEmpty();
}

- (NSData *)key {
    const VirgilByteArray &keyArr = self.cppPfsPublicKey->getKey();
    return [NSData dataWithBytes:keyArr.data() length:keyArr.size()];
}

- (void)dealloc {
    delete self.cppPfsPublicKey;
}

@end
