//
//  VSSKeyPair.mm
//  VirgilFoundation
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import "VSSKeyPair.h"
#import <VirgilCrypto/virgil/crypto/VirgilByteArray.h>
#import <VirgilCrypto/virgil/crypto/VirgilKeyPair.h>

using virgil::crypto::VirgilByteArray;
using namespace virgil::crypto;

@interface VSSKeyPair ()

@property (nonatomic, assign) VirgilKeyPair * __nullable keyPair;

- (instancetype __nonnull)initWithVirgilKeyPair:(VirgilKeyPair)candidate NS_DESIGNATED_INITIALIZER;

@end

@implementation VSSKeyPair

@synthesize keyPair = _keyPair;

#pragma mark - Lifecycle

- (instancetype)init {
    return [self initWithPassword:nil];
}

- (instancetype)initWithPassword:(NSString *)password {
    self = [super init];
    if( nil == self ) {
        return nil;
    }
    if( 0 >= [password length] ) {
        _keyPair = new VirgilKeyPair();
    } else {
        std::string pwd = std::string([password UTF8String]);
        _keyPair = new VirgilKeyPair(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pwd.data(), pwd.size()));
    }
    return self;
}

- (instancetype __nonnull)initWithVirgilKeyPair:(VirgilKeyPair)candidate {
    self = [super init];
    if( nil == self ) {
        return nil;
    }
    
    _keyPair = new VirgilKeyPair(candidate);
    return self;
}

- (void)dealloc {
    if (_keyPair != NULL) {
        delete _keyPair;
        _keyPair = NULL;
    }
}

- (instancetype __nonnull)initECNist192WithPassword:(NSString * __nullable)password {
    VirgilKeyPair candidate;
    if( 0 >= [password length] ) {
        candidate = VirgilKeyPair::ecNist192();
    }
    else {
        std::string pwd = std::string([password UTF8String]);
        candidate = VirgilKeyPair::ecNist192(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pwd.data(), pwd.size()));
    }
    return [self initWithVirgilKeyPair:candidate];
}

- (instancetype __nonnull)initECNist224WithPassword:(NSString * __nullable)password {
    VirgilKeyPair candidate;
    if( 0 >= [password length] ) {
        candidate = VirgilKeyPair::ecNist224();
    }
    else {
        std::string pwd = std::string([password UTF8String]);
        candidate = VirgilKeyPair::ecNist224(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pwd.data(), pwd.size()));
    }
    return [self initWithVirgilKeyPair:candidate];
}

- (instancetype __nonnull)initECNist256WithPassword:(NSString * __nullable)password {
    VirgilKeyPair candidate;
    if( 0 >= [password length] ) {
        candidate = VirgilKeyPair::ecNist256();
    }
    else {
        std::string pwd = std::string([password UTF8String]);
        candidate = VirgilKeyPair::ecNist256(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pwd.data(), pwd.size()));
    }
    return [self initWithVirgilKeyPair:candidate];
}

- (instancetype __nonnull)initECNist384WithPassword:(NSString * __nullable)password {
    VirgilKeyPair candidate;
    if( 0 >= [password length] ) {
        candidate = VirgilKeyPair::ecNist384();
    }
    else {
        std::string pwd = std::string([password UTF8String]);
        candidate = VirgilKeyPair::ecNist384(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pwd.data(), pwd.size()));
    }
    return [self initWithVirgilKeyPair:candidate];
}

- (instancetype __nonnull)initECNist521WithPassword:(NSString * __nullable)password {
    VirgilKeyPair candidate;
    if( 0 >= [password length] ) {
        candidate = VirgilKeyPair::ecNist521();
    }
    else {
        std::string pwd = std::string([password UTF8String]);
        candidate = VirgilKeyPair::ecNist521(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pwd.data(), pwd.size()));
    }
    return [self initWithVirgilKeyPair:candidate];
}

- (instancetype __nonnull)initECBrainpool256WithPassword:(NSString * __nullable)password {
    VirgilKeyPair candidate;
    if( 0 >= [password length] ) {
        candidate = VirgilKeyPair::ecBrainpool256();
    }
    else {
        std::string pwd = std::string([password UTF8String]);
        candidate = VirgilKeyPair::ecBrainpool256(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pwd.data(), pwd.size()));
    }
    return [self initWithVirgilKeyPair:candidate];
}

- (instancetype __nonnull)initECBrainpool384WithPassword:(NSString * __nullable)password {
    VirgilKeyPair candidate;
    if( 0 >= [password length] ) {
        candidate = VirgilKeyPair::ecBrainpool384();
    }
    else {
        std::string pwd = std::string([password UTF8String]);
        candidate = VirgilKeyPair::ecBrainpool384(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pwd.data(), pwd.size()));
    }
    return [self initWithVirgilKeyPair:candidate];
}

- (instancetype __nonnull)initECBrainpool512WithPassword:(NSString * __nullable)password {
    VirgilKeyPair candidate;
    if( 0 >= [password length] ) {
        candidate = VirgilKeyPair::ecBrainpool512();
    }
    else {
        std::string pwd = std::string([password UTF8String]);
        candidate = VirgilKeyPair::ecBrainpool512(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pwd.data(), pwd.size()));
    }
    return [self initWithVirgilKeyPair:candidate];
}

- (instancetype __nonnull)initECKoblitz192WithPassword:(NSString * __nullable)password {
    VirgilKeyPair candidate;
    if( 0 >= [password length] ) {
        candidate = VirgilKeyPair::ecKoblitz192();
    }
    else {
        std::string pwd = std::string([password UTF8String]);
        candidate = VirgilKeyPair::ecKoblitz192(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pwd.data(), pwd.size()));
    }
    return [self initWithVirgilKeyPair:candidate];
}

- (instancetype __nonnull)initECKoblitz224WithPassword:(NSString * __nullable)password {
    VirgilKeyPair candidate;
    if( 0 >= [password length] ) {
        candidate = VirgilKeyPair::ecKoblitz224();
    }
    else {
        std::string pwd = std::string([password UTF8String]);
        candidate = VirgilKeyPair::ecKoblitz224(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pwd.data(), pwd.size()));
    }
    return [self initWithVirgilKeyPair:candidate];
}

- (instancetype __nonnull)initECKoblitz256WithPassword:(NSString * __nullable)password {
    VirgilKeyPair candidate;
    if( 0 >= [password length] ) {
        candidate = VirgilKeyPair::ecKoblitz256();
    }
    else {
        std::string pwd = std::string([password UTF8String]);
        candidate = VirgilKeyPair::ecKoblitz256(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pwd.data(), pwd.size()));
    }
    return [self initWithVirgilKeyPair:candidate];
}

- (instancetype __nonnull)initRSA256WithPassword:(NSString * __nullable)password {
    VirgilKeyPair candidate;
    if( 0 >= [password length] ) {
        candidate = VirgilKeyPair::rsa256();
    }
    else {
        std::string pwd = std::string([password UTF8String]);
        candidate = VirgilKeyPair::rsa256(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pwd.data(), pwd.size()));
    }
    return [self initWithVirgilKeyPair:candidate];
}

- (instancetype __nonnull)initRSA512WithPassword:(NSString * __nullable)password {
    VirgilKeyPair candidate;
    if( 0 >= [password length] ) {
        candidate = VirgilKeyPair::rsa512();
    }
    else {
        std::string pwd = std::string([password UTF8String]);
        candidate = VirgilKeyPair::rsa512(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pwd.data(), pwd.size()));
    }
    return [self initWithVirgilKeyPair:candidate];
}

- (instancetype __nonnull)initRSA1024WithPassword:(NSString * __nullable)password {
    VirgilKeyPair candidate;
    if( 0 >= [password length] ) {
        candidate = VirgilKeyPair::rsa1024();
    }
    else {
        std::string pwd = std::string([password UTF8String]);
        candidate = VirgilKeyPair::rsa1024(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pwd.data(), pwd.size()));
    }
    return [self initWithVirgilKeyPair:candidate];
}

- (instancetype __nonnull)initRSA2048WithPassword:(NSString * __nullable)password {
    VirgilKeyPair candidate;
    if( 0 >= [password length] ) {
        candidate = VirgilKeyPair::rsa2048();
    }
    else {
        std::string pwd = std::string([password UTF8String]);
        candidate = VirgilKeyPair::rsa2048(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pwd.data(), pwd.size()));
    }
    return [self initWithVirgilKeyPair:candidate];
}

- (instancetype __nonnull)initRSA4096WithPassword:(NSString * __nullable)password {
    VirgilKeyPair candidate;
    if( 0 >= [password length] ) {
        candidate = VirgilKeyPair::rsa4096();
    }
    else {
        std::string pwd = std::string([password UTF8String]);
        candidate = VirgilKeyPair::rsa4096(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pwd.data(), pwd.size()));
    }
    return [self initWithVirgilKeyPair:candidate];
}

#pragma mark - Public class logic

- (NSData *)publicKey {
    if( self.keyPair == NULL ) {
        return [NSData data];
    }
    NSData *publicKey = nil;

    VirgilByteArray pkey = self.keyPair->publicKey();
    publicKey = [NSData dataWithBytes:pkey.data() length:pkey.size()];
    return publicKey;
}

- (NSData *)privateKey {
    if( self.keyPair == NULL ) {
        return [NSData data];
    }
    
    NSData *privateKey = nil;
    VirgilByteArray pkey = self.keyPair->privateKey();
    privateKey = [NSData dataWithBytes:pkey.data() length:pkey.size()];
    return privateKey;
}

@end
