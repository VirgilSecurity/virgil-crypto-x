//
// Created by Yaroslav Tytarenko on 10/5/16.
// Copyright (c) 2016 VirgilSecurity. All rights reserved.
//

#import "VSCHash.h"
#import <VSCCrypto/virgil/crypto/foundation/VirgilHash.h>
#import <VSCCrypto/virgil/crypto/VirgilKeyPair.h>
#include <CommonCrypto/CommonDigest.h>

using virgil::crypto::foundation::VirgilHash;
using virgil::crypto::VirgilByteArray;
using CAlgorithm = virgil::crypto::foundation::VirgilHash::Algorithm;


@interface VSCHash ()

@property(nonatomic, assign) VirgilHash *hash;
@property(nonatomic, strong) NSDictionary *enumsDict;
@property(nonatomic, strong) NSDictionary *digestLenghtDict;
@property(nonatomic, assign) VSCAlgorithm currentAlgorithm;

@end

@implementation VSCHash

@synthesize hash = _hash;

- (instancetype)initWithAlgorithm:(VSCAlgorithm)algorithm {
    self = [super init];
    if (!self) {
        return nil;
    }

    self.currentAlgorithm = algorithm;
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

    self.digestLenghtDict = @{
            @(VSCMD5): @CC_MD5_DIGEST_LENGTH,
            @(VSCSHA1): @CC_SHA1_DIGEST_LENGTH,
            @(VSCSHA224): @CC_SHA224_DIGEST_LENGTH,
            @(VSCSHA256): @CC_SHA256_DIGEST_LENGTH,
            @(VSCSHA384): @CC_SHA384_DIGEST_LENGTH,
            @(VSCSHA512): @CC_SHA512_DIGEST_LENGTH,
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
    if (!data || data.length == 0) {
        return VirgilByteArray();
    }

    const unsigned char *dataToEncrypt = static_cast<const unsigned char *>(data.bytes);
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(dataToEncrypt, [data length]);
}

#pragma mark - Public

- (NSData *)hash:(NSData *)data {
    if (!data || data.length == 0) {
        return nil;
    }

    const VirgilByteArray vData = [self convertVirgilByteArrayFromData:data];
    const VirgilByteArray hashData = self.hash->hash(vData);
    NSMutableString *output = [NSMutableString stringWithCapacity:hashData.size() * 2];
    NSNumber *num = self.digestLenghtDict[@(self.currentAlgorithm)];

    for (int i = 0; i < num.longLongValue; i++) {
        [output appendFormat:@"%02x", hashData[i]];
    }

    return [output dataUsingEncoding:NSUTF8StringEncoding];
}

@end
