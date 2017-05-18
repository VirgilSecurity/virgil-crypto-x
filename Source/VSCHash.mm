//
// Created by Yaroslav Tytarenko on 10/5/16.
// Copyright (c) 2016 VirgilSecurity. All rights reserved.
//

#import "VSCHash.h"
#import <virgil/crypto/foundation/VirgilHash.h>
#import <virgil/crypto/VirgilKeyPair.h>

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

- (VirgilByteArray)convertVirgilByteArrayFromData:(NSData *)data {
    if (data.length == 0) {
        return VirgilByteArray();
    }

    const unsigned char *dataToEncrypt = static_cast<const unsigned char *>(data.bytes);
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(dataToEncrypt, [data length]);
}

#pragma mark - Public

- (NSData *)hash:(NSData *)data {
    const VirgilByteArray &vData = [self convertVirgilByteArrayFromData:data];
    const VirgilByteArray &hashData = self.hash->hash(vData);

    return [NSData dataWithBytes:hashData.data() length:hashData.size()];
}

@end
