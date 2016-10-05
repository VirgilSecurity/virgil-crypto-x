//
// Created by Yaroslav Tytarenko on 10/5/16.
// Copyright (c) 2016 VirgilSecurity. All rights reserved.
//

#import "VSCHash.h"
#import <VSCCrypto/virgil/crypto/foundation/VirgilHash.h>
#import <VSCCrypto/virgil/crypto/VirgilKeyPair.h>

using virgil::crypto::foundation::VirgilHash;
using virgil::crypto::VirgilByteArray;
using CAlgorithm = virgil::crypto::foundation::VirgilHash::Algorithm;


@interface VSCHash ()

@property(nonatomic, assign) VirgilHash *hash;
@property(nonatomic, strong) NSDictionary *enumsDict;

@end

@implementation VSCHash

@synthesize hash = _hash;

- (instancetype)initWithAlgorithm:(VSCAlgorithm)algorithm {
    self = [super init];
    if (!self) {
        return nil;
    }

    [self initializeDictionaries];

    _hash = new VirgilHash([self convertVSCAlgorithmToCAlgorithm:algorithm]);

    return self;
}

- (void)initializeDictionaries {
    self.enumsDict = @{
            @(VSCMD5): [self valueFromCType:CAlgorithm::MD5],
            @(VSCSHA1): [self valueFromCType:CAlgorithm::SHA1],
            @(VSCSHA224): [self valueFromCType:CAlgorithm::SHA224],
            @(VSCSHA256): [self valueFromCType:CAlgorithm::SHA256],
            @(VSCSHA384): [self valueFromCType:CAlgorithm::SHA384],
            @(VSCSHA512): [self valueFromCType:CAlgorithm::SHA512],
    };
}

- (void)dealloc {
    if (_hash != NULL) {
        delete _hash;
        _hash = NULL;
    }
}

#pragma mark - Private

- (NSValue *)valueFromCType:(CAlgorithm)type {
    return [NSValue value:(const void *) &type withObjCType:@encode(VirgilHash::Algorithm)];
}

- (CAlgorithm)cAlgorithmFromValue:(NSValue *)value {
    return (CAlgorithm) reinterpret_cast<int64_t >(value.pointerValue);
}

- (CAlgorithm)convertVSCAlgorithmToCAlgorithm:(VSCAlgorithm)keyType {
    return [self cAlgorithmFromValue:self.enumsDict[@(keyType)]];
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
    if (data.length == 0) {
        return nil;
    }

    const VirgilByteArray &vData = [self convertVirgilByteArrayFromData:data];
    const VirgilByteArray &hashData = self.hash->hash(vData);

    return [NSData dataWithBytes:hashData.data() length:hashData.size()];
}

@end
