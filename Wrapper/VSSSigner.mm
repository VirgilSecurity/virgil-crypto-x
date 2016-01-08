//
//  VSSSigner.mm
//  VirgilFoundation
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

/// In the MacOSX SDK there is a macro definition which covers signer->verify method.
/// So we need to disable it for this.
#ifdef verify
# undef verify
#endif

#import "VSSSigner.h"
#import <VirgilCrypto/virgil/crypto/VirgilByteArray.h>
#import <VirgilCrypto/virgil/crypto/VirgilSigner.h>
#import <VirgilCrypto/virgil/crypto/foundation/VirgilHash.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilSigner;
using virgil::crypto::foundation::VirgilHash;

NSString* const kHashNameMD5 = @"md5";
NSString* const kHashNameSHA256 = @"sha256";
NSString* const kHashNameSHA384 = @"sha384";
NSString* const kHashNameSHA512 = @"sha512";

@interface VSSSigner ()

@property (nonatomic, assign) VirgilSigner * __nullable signer;

@end

@implementation VSSSigner

@synthesize signer = _signer;

#pragma mark - Lifecycle

- (instancetype)init {
    return [self initWithHash:nil];
}

- (instancetype) initWithHash:(NSString *)hash {
    self = [super init];
    if (self == nil) {
        return nil;
    }
    if ([hash isEqualToString:kHashNameMD5]) {
        _signer = new VirgilSigner(VirgilHash::md5());
    }
    else if ([hash isEqualToString:kHashNameSHA256]) {
        _signer = new VirgilSigner(VirgilHash::sha256());
    }
    else if ([hash isEqualToString:kHashNameSHA384]) {
        _signer = new VirgilSigner(VirgilHash::sha384());
    }
    else if ([hash isEqualToString:kHashNameSHA512]) {
        _signer = new VirgilSigner(VirgilHash::sha512());
    }
    else if (hash.length > 0)
    {
        std::string hashName = std::string([hash UTF8String]);
        VirgilByteArray hashNameArray = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(hashName.data(), hashName.size());
        _signer = new VirgilSigner(VirgilHash::withName(hashNameArray));
    }
    else {
        _signer = new VirgilSigner();
    }
    return self;
}

- (void)dealloc {
    if (_signer != NULL) {
        delete _signer;
        _signer = NULL;
    }
}

#pragma mark - Public class logic

- (NSData *)signData:(NSData *)data privateKey:(NSData *)privateKey keyPassword:(NSString *)keyPassword {
    if (data.length == 0 || privateKey.length == 0) {
        return nil;
    }
    
    NSData *signData = nil;
    if (self.signer != NULL) {
        // Convert NSData to
        const char *dataToSign = (const char *)[data bytes];
        VirgilByteArray plainData = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(dataToSign, [data length]);
        // Convert NSData to
        const char *pKeyData = (const char *)[privateKey bytes];
        VirgilByteArray pKey = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pKeyData, [privateKey length]);
        
        VirgilByteArray sign;
        if (keyPassword.length > 0) {
            std::string pKeyPassS = std::string([keyPassword UTF8String]);
            VirgilByteArray pKeyPassword = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pKeyPassS.data(), pKeyPassS.size());
            sign = self.signer->sign(plainData, pKey, pKeyPassword);
        }
        else {
            sign = self.signer->sign(plainData, pKey);
        }
        signData = [NSData dataWithBytes:sign.data() length:sign.size()];
    }
    return signData;
}

- (BOOL)verifySignature:(NSData *)signature data:(NSData *)data publicKey:(NSData *)publicKey {
    if (data.length == 0 || signature.length == 0 || publicKey.length == 0) {
        return NO;
    }
    
    BOOL verified = NO;
    if (self.signer != NULL) {
        // Convert NSData data
        const char *signedDataPtr = (const char *)[data bytes];
        VirgilByteArray signedData = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(signedDataPtr, [data length]);
        // Convert NSData sign
        const char *signDataPtr = (const char *)[signature bytes];
        VirgilByteArray signData = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(signDataPtr, [signature length]);
        // Convert NSData Key
        const char *keyDataPtr = (const char *)[publicKey bytes];
        VirgilByteArray pKey = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(keyDataPtr, [publicKey length]);
        
        bool result = self.signer->verify(signedData, signData, pKey);
        if (result) {
            verified = YES;
        }
        else {
            verified = NO;
        }
    }
    return verified;
}

@end
