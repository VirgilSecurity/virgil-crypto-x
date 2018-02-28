//
// Created by Yaroslav Tytarenko on 10/5/16.
// Copyright (c) 2016 VirgilSecurity. All rights reserved.
//

#import "VSCHash.h"
#import "VSCByteArrayUtilsPrivate.h"

#import <VSCCrypto/VirgilCrypto.h>

using virgil::crypto::foundation::VirgilHash;
using virgil::crypto::VirgilByteArray;
using CAlgorithm = virgil::crypto::foundation::VirgilHash::Algorithm;


@interface VSCHash ()

@property(nonatomic, assign) VirgilHash *hash;

@end

@implementation VSCHash

@synthesize hash = _hash;

- (instancetype)initWithAlgorithm:(VSCHashAlgorithm)algorithm {
    self = [super init];
    if (!self) {
        return nil;
    }

    _hash = new VirgilHash([self convertVSCAlgorithmToCAlgorithm:algorithm]);

    return self;
}

- (void)dealloc {
    if (_hash != NULL) {
        delete _hash;
        _hash = NULL;
    }
}

#pragma mark - Private

- (CAlgorithm)convertVSCAlgorithmToCAlgorithm:(VSCHashAlgorithm)keyType {
    CAlgorithm result;
    switch (keyType) {
        case VSCHashAlgorithmMD5:
            result = CAlgorithm::MD5;
            break;
        case VSCHashAlgorithmSHA1:
            result = CAlgorithm::SHA1;
            break;
        case VSCHashAlgorithmSHA224:
            result = CAlgorithm::SHA224;
            break;
        case VSCHashAlgorithmSHA256:
            result = CAlgorithm::SHA256;
            break;
        case VSCHashAlgorithmSHA384:
            result = CAlgorithm::SHA384;
            break;
        case VSCHashAlgorithmSHA512:
            result = CAlgorithm::SHA512;
            break;
    }
    return result;
}

#pragma mark - Public

- (NSData *)hash:(NSData *)data {
    const VirgilByteArray &vData = [VSCByteArrayUtils convertVirgilByteArrayFromData:data];
    const VirgilByteArray &hashData = self.hash->hash(vData);

    return [NSData dataWithBytes:hashData.data() length:hashData.size()];
}

- (void)start {
    self.hash->start();
}

- (void)updateWithData:(NSData *)data {
    const VirgilByteArray &vData = [VSCByteArrayUtils convertVirgilByteArrayFromData:data];
    self.hash->update(vData);
}

- (NSData *)finish {
    const VirgilByteArray &hashData = self.hash->finish();
    
    return [NSData dataWithBytes:hashData.data() length:hashData.size()];
}

@end
