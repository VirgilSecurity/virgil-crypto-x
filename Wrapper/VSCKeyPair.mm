//
//  VSCKeyPair.mm
//  VirgilFoundation
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import "VSCKeyPair.h"
#import <VSCCrypto/virgil/crypto/VirgilByteArray.h>
#import <VSCCrypto/virgil/crypto/VirgilKeyPair.h>

using virgil::crypto::VirgilByteArray;
using CType = virgil::crypto::VirgilKeyPair::Type;
using namespace virgil::crypto;

NSString *const kVSSKeyPairErrorDomain = @"VSSKeyPairErrorDomain";

@interface VSCKeyPair ()

@property (nonatomic, assign) VirgilKeyPair *keyPair;
@property (nonatomic, strong) NSDictionary *enumsDict;

- (NSValue *)valueFromCType:(CType)type;
- (CType)ctypeFromValue:(NSValue *)value;
- (CType)convertVSCKeyTypeToCType:(VSCKeyType)keyType;

+ (VirgilByteArray)convertVirgilByteArrayFromData:(NSData *)data;
+ (VirgilByteArray)convertVirgilByteArrayFromString:(NSString *)string;

@end


@implementation VSCKeyPair

@synthesize keyPair = _keyPair;

#pragma mark - Lifecycle

- (instancetype)initWithKeyPairType:(VSCKeyType)keyPairType password:(NSString *)password {
    self = [super init];
    if (self == nil) {
        return nil;
    }
    
    [self initializeEnumsDictionary];
    
    try {
        CType type = [self convertVSCKeyTypeToCType:keyPairType];
        if (password.length == 0) {
            _keyPair = new VirgilKeyPair(VirgilKeyPair::generate(type));
        }
        else {
            const VirgilByteArray &pwd = [VSCKeyPair convertVirgilByteArrayFromString:password];
            _keyPair = new VirgilKeyPair(VirgilKeyPair::generate(type, pwd));
        }
    }
    catch(...) {
        _keyPair = NULL;
    }
    
    return self;
}

- (instancetype)init {
    self = [super init];
    if (self == nil) {
        return nil;
    }

    try {
        _keyPair = new VirgilKeyPair(VirgilKeyPair::generateRecommended());
    }
    catch(...) {
        _keyPair = NULL;
    }
    
    return self;
}

- (void)dealloc {
    if (_keyPair != NULL) {
        delete _keyPair;
        _keyPair = NULL;
    }
}

#pragma mark - Private

- (void)initializeEnumsDictionary {
    self.enumsDict = @{
        @(VSCKeyTypeRSA_256) : [self valueFromCType:CType::RSA_256],
        @(VSCKeyTypeRSA_512) : [self valueFromCType:CType::RSA_512],
        @(VSCKeyTypeRSA_1024) : [self valueFromCType:CType::RSA_1024],
        @(VSCKeyTypeRSA_2048) : [self valueFromCType:CType::RSA_2048],
        @(VSCKeyTypeRSA_3072) : [self valueFromCType:CType::RSA_3072],
        @(VSCKeyTypeRSA_4096) : [self valueFromCType:CType::RSA_4096],
        @(VSCKeyTypeRSA_8192) : [self valueFromCType:CType::RSA_8192],
        @(VSCKeyTypeEC_SECP192R1) : [self valueFromCType:CType::EC_SECP192R1],
        @(VSCKeyTypeEC_SECP224R1) : [self valueFromCType:CType::EC_SECP224R1],
        @(VSCKeyTypeEC_SECP256R1) : [self valueFromCType:CType::EC_SECP256R1],
        @(VSCKeyTypeEC_SECP384R1) : [self valueFromCType:CType::EC_SECP384R1],
        @(VSCKeyTypeEC_SECP521R1) : [self valueFromCType:CType::EC_SECP521R1],
        @(VSCKeyTypeEC_BP256R1) : [self valueFromCType:CType::EC_BP256R1],
        @(VSCKeyTypeEC_BP384R1) : [self valueFromCType:CType::EC_BP384R1],
        @(VSCKeyTypeEC_BP512R1) : [self valueFromCType:CType::EC_BP512R1],
        @(VSCKeyTypeEC_SECP192K1) : [self valueFromCType:CType::EC_SECP192K1],
        @(VSCKeyTypeEC_SECP224K1) : [self valueFromCType:CType::EC_SECP224K1],
        @(VSCKeyTypeEC_SECP256K1) : [self valueFromCType:CType::EC_SECP256K1],
        @(VSCKeyTypeEC_CURVE25519) : [self valueFromCType:CType::EC_CURVE25519],
        @(VSCKeyTypeFAST_EC_X25519) : [self valueFromCType:CType::FAST_EC_X25519],
        @(VSCKeyTypeFAST_EC_ED25519) : [self valueFromCType:CType::FAST_EC_ED25519],
    };
}

- (NSValue *)valueFromCType:(CType)type {
    return [NSValue value:(const void *) &type withObjCType:@encode(VirgilKeyPair::Type)];
}

- (CType)ctypeFromValue:(NSValue *)value {
    return (CType)reinterpret_cast<int>(value.pointerValue);
}

- (CType)convertVSCKeyTypeToCType:(VSCKeyType)keyType {
    return [self ctypeFromValue:self.enumsDict[@(keyType)]];
}

+ (VirgilByteArray)convertVirgilByteArrayFromData:(NSData *)data {
    if (!data || data.length == 0) {
        return VirgilByteArray();
    }

    const unsigned char *dataToEncrypt = static_cast<const unsigned char *>(data.bytes);
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(dataToEncrypt, [data length]);
}

+ (VirgilByteArray)convertVirgilByteArrayFromString:(NSString *)string {
    if (!string || string.length == 0) {
        return VirgilByteArray();
    }

    std::string pass = std::string(string.UTF8String);
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pass.data(), pass.size());
}

#pragma mark - Public

- (NSData *)publicKey {
    if( self.keyPair == NULL ) {
        return [NSData data];
    }
    NSData *publicKey = nil;
    try {
        VirgilByteArray pkey = self.keyPair->publicKey();
        publicKey = [NSData dataWithBytes:pkey.data() length:pkey.size()];
    }
    catch(...) {
        publicKey = [NSData data];
    }
    return publicKey;
}

- (NSData *)privateKey {
    if( self.keyPair == NULL ) {
        return [NSData data];
    }
    
    NSData *privateKey = nil;
    try {
        VirgilByteArray pkey = self.keyPair->privateKey();
        privateKey = [NSData dataWithBytes:pkey.data() length:pkey.size()];
    }
    catch(...) {
        privateKey = [NSData data];
    }
    return privateKey;
}

+ (NSData *__nonnull)encryptPrivateKey:(NSData *)privateKey privateKeyPassword:(NSString *)password {
    if(!privateKey || !password) {
        return [NSData data];
    }

    NSData *encryptedPrivateKey = nil;
    try {
        const VirgilByteArray &prvtKey = [self convertVirgilByteArrayFromData:privateKey];
        const VirgilByteArray &pass = [self convertVirgilByteArrayFromString:password];
        VirgilByteArray array = VirgilKeyPair::encryptPrivateKey(prvtKey, pass);
        encryptedPrivateKey = [NSData dataWithBytes:array.data() length:array.size()];
    }
    catch (...) {
        encryptedPrivateKey = [NSData data];
    }

    return encryptedPrivateKey;
}

+ (NSData *__nonnull)decryptPrivateKey:(NSData *)privateKey privateKeyPassword:(NSString *)password {
    if(!privateKey || !password) {
        return [NSData data];
    }

    NSData *decryptedPrivateKey = nil;

    try {
        const VirgilByteArray &prvtKey = [self convertVirgilByteArrayFromData:privateKey];
        const VirgilByteArray &pass = [self convertVirgilByteArrayFromString:password];
        VirgilByteArray array = VirgilKeyPair::decryptPrivateKey(prvtKey, pass);
        decryptedPrivateKey = [NSData dataWithBytes:array.data() length:array.size()];
    }
    catch (...) {
        decryptedPrivateKey = [NSData data];
    }

    return decryptedPrivateKey;
}

+ (BOOL)isEncryptedPrivateKey:(NSData *)keyData {
    if (keyData.length == 0) {
        return NO;
    }
    
    BOOL isEncrypted;
    try {
        const unsigned char *data = static_cast<const unsigned char *>(keyData.bytes);
        isEncrypted = VirgilKeyPair::isPrivateKeyEncrypted(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(data, [keyData length]));
    }
    catch(...) {
        isEncrypted = false;
    }

    return isEncrypted;

}

+ (BOOL)isPrivateKey:(NSData *)keyData matchesPassword:(NSString *)password {
    if (keyData.length == 0 || password.length == 0) {
        return NO;
    }
    
    BOOL isMatches;
    try {
        const unsigned char *data = static_cast<const unsigned char *>(keyData.bytes);
        std::string pwd = std::string(password.UTF8String);
        isMatches = VirgilKeyPair::checkPrivateKeyPassword(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(data, [keyData length]), VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pwd.data(), pwd.size()));
    }
    catch(...) {
        isMatches = false;
    }

    return isMatches;

}

+ (BOOL)isPublicKey:(NSData *)publicKeyData matchesPrivateKey:(NSData *)privateKeyData withPassword:(NSString *)password {
    if (publicKeyData.length == 0 || privateKeyData.length == 0) {
        return NO;
    }
    
    BOOL isMatches;
    try {
        const unsigned char *pubKeyData = static_cast<const unsigned char *>(publicKeyData.bytes);
        const unsigned char *privKeyData = static_cast<const unsigned char *>(privateKeyData.bytes);
        if (password.length == 0) {
            isMatches = VirgilKeyPair::isKeyPairMatch(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pubKeyData, [publicKeyData length]), VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(privKeyData, [privateKeyData length]));
        }
        else {
            std::string pwd = std::string(password.UTF8String);
            isMatches = VirgilKeyPair::isKeyPairMatch(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pubKeyData, [publicKeyData length]), VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(privKeyData, [privateKeyData length]), VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pwd.data(), pwd.size()));
        }
    }
    catch(...) {
        isMatches = false;
    }

    return isMatches;

}

+ (NSData * __nullable)resetPassword:(NSString *)password toPassword:(NSString *)newPassword forPrivateKey:(NSData *)keyData error:(NSError **)error {
    if (password.length == 0 || newPassword.length == 0 || keyData.length == 0) {
        // Can't reset password.
        if (error) {
            *error = [NSError errorWithDomain:kVSSKeyPairErrorDomain code:-1000 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to reset password: Required parameter is missing.", @"Reset password error.") }];
        }
        return nil;
    }
    
    NSData *pkeyData = nil;
    try {
        std::string sPwd = std::string(password.UTF8String);
        VirgilByteArray vbaPwd = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(sPwd.data(), sPwd.size());
        
        std::string sNewPwd = std::string(newPassword.UTF8String);
        VirgilByteArray vbaNewPwd = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(sNewPwd.data(), sNewPwd.size());
        
        const unsigned char *pKeyData = static_cast<const unsigned char *>(keyData.bytes);
        VirgilByteArray pKey = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pKeyData, [keyData length]);
        
        VirgilByteArray pNewKey = VirgilKeyPair::resetPrivateKeyPassword(pKey, vbaPwd, vbaNewPwd);
        pkeyData = [NSData dataWithBytes:pNewKey.data() length:pNewKey.size()];
        if (error) {
            *error = nil;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during password reset.";
            }
            *error = [NSError errorWithDomain:kVSSKeyPairErrorDomain code:-1001 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        pkeyData = nil;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSSKeyPairErrorDomain code:-1002 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during password reset." }];
        }
        pkeyData = nil;
    }
    
    return pkeyData;
}

+ (NSData *)publicKeyToPEM:(NSData *)publicKey {
    if(!publicKey) {
        return [NSData data];
    }

    NSData *pemData = nil;

    try {
        const VirgilByteArray &pubKey = [self convertVirgilByteArrayFromData:publicKey];
        const VirgilByteArray &array = VirgilKeyPair::publicKeyToPEM(pubKey);
        pemData = [NSData dataWithBytes:array.data() length:array.size()];
    }
    catch (...) {
        pemData = [NSData data];
    }

    return pemData;
}

+ (NSData *)publicKeyToDER:(NSData *)publicKey {
    if(!publicKey) {
        return [NSData data];
    }

    NSData *result = nil;

    try {
        const VirgilByteArray &key = [self convertVirgilByteArrayFromData:publicKey];
        const VirgilByteArray &der = VirgilKeyPair::publicKeyToDER(key);
        result = [NSData dataWithBytes:der.data() length:der.size()];
    }
    catch (...) {
        result = [NSData data];
    }

    return result;
}

+ (NSData *)privateKeyToPEM:(NSData *)privateKey {
    return [VSCKeyPair privateKeyToPEM:privateKey privateKeyPassword:nil];
}

+ (NSData *)privateKeyToDER:(NSData *)privateKey {
    return [VSCKeyPair privateKeyToDER:privateKey privateKeyPassword:nil];
}

+ (NSData *)privateKeyToPEM:(NSData *)privateKey privateKeyPassword:(NSString *)password {
    if(!privateKey) {
        return [NSData data];
    }

    NSData *result = nil;

    try {
        const VirgilByteArray &pass = [self convertVirgilByteArrayFromString:password];
        const VirgilByteArray &key = [self convertVirgilByteArrayFromData:privateKey];
        const VirgilByteArray &pem = VirgilKeyPair::privateKeyToPEM(key, pass);

        result = [NSData dataWithBytes:pem.data() length:pem.size()];
    }
    catch (...) {
        result = [NSData data];
    }

    return result;
}

+ (NSData *)privateKeyToDER:(NSData *)privateKey privateKeyPassword:(NSString *)password {
    if(!privateKey) {
        return [NSData data];
    }

    NSData *result = nil;

    try {
        const VirgilByteArray &pass = [self convertVirgilByteArrayFromString:password];
        const VirgilByteArray &key = [self convertVirgilByteArrayFromData:privateKey];
        const VirgilByteArray &der = VirgilKeyPair::privateKeyToDER(key, pass);

        result = [NSData dataWithBytes:der.data() length:der.size()];
    }
    catch (...) {
        result = [NSData data];
    }

    return result;
}

@end
