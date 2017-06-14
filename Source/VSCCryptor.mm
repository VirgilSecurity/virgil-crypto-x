//
//  VSCCryptor.mm
//  VirgilFoundation
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import "VSCCryptor.h"
#import "VSCBaseCryptorPrivate.h"
#import "VSCByteArrayUtilsPrivate.h"
#import <virgil/crypto/VirgilCipher.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilCipher;

NSString *const kVSCCryptorErrorDomain = @"VSCCryptorErrorDomain";

@interface VSCCryptor ()

- (VirgilCipher *)cryptor;

@end

@implementation VSCCryptor

#pragma mark - Lifecycle

- (void)initializeCryptor {
    if (self.llCryptor != NULL) {
        // llCryptor has been initialized already.
        return;
    }
    
    try {
        self.llCryptor = new VirgilCipher();
    }
    catch(...) {
        self.llCryptor = NULL;
    }
}

- (void)dealloc {
    if (self.llCryptor != NULL) {
        delete (VirgilCipher *)self.llCryptor;
        self.llCryptor = NULL;
    }
}

- (VirgilCipher *)cryptor {
    if (self.llCryptor == NULL) {
        return NULL;
    }
    
    return static_cast<VirgilCipher *>(self.llCryptor);
}

#pragma mark - Public class logic

- (NSData *)encryptData:(NSData *)plainData embedContentInfo:(NSNumber *) embedContentInfo {
    return [self encryptData:plainData embedContentInfo:embedContentInfo.boolValue error:nil];
}

- (NSData *)encryptData:(NSData *)plainData embedContentInfo:(BOOL)embedContentInfo error:(NSError **)error {
    if (plainData.length == 0) {
        // Can't encrypt.
        if (error) {
            *error = [NSError errorWithDomain:kVSCCryptorErrorDomain code:-1000 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to encrypt: Required parameter is missing.", @"Encrypt data error.") }];
        }
        return nil;
    }
    
    NSData *encData = nil;
    try {
        if ([self cryptor] != NULL) {
            VirgilByteArray plainDataArray = [VSCByteArrayUtils convertVirgilByteArrayFromData:plainData];

            // Encrypt data.
            VirgilByteArray encryptedData = [self cryptor]->encrypt(plainDataArray, (bool)embedContentInfo);
            encData = [NSData dataWithBytes:encryptedData.data() length:encryptedData.size()];
            if (error) {
                *error = nil;
            }
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCCryptorErrorDomain code:-1001 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to encrypt. Cryptor is not initialized properly." }];
            }
            encData = nil;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during encryption.";
            }
            *error = [NSError errorWithDomain:kVSCCryptorErrorDomain code:-1002 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        encData = nil;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCCryptorErrorDomain code:-1003 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during encryption." }];
        }
        encData = nil;
    }
    
    return encData;
}

- (NSData *)decryptData:(NSData *)encryptedData recipientId:(NSData *)recipientId privateKey:(NSData *)privateKey keyPassword:(NSString *)keyPassword {
    return [self decryptData:encryptedData recipientId:recipientId privateKey:privateKey keyPassword:keyPassword error:nil];
}

- (NSData *)decryptData:(NSData *)encryptedData recipientId:(NSData *)recipientId privateKey:(NSData *)privateKey keyPassword:(NSString *)keyPassword error:(NSError **)error {
    if (encryptedData.length == 0 || recipientId.length == 0 || privateKey.length == 0) {
        // Can't decrypt
        if (error) {
            *error = [NSError errorWithDomain:kVSCCryptorErrorDomain code:-1004 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to decrypt with key: At least one of the required parameters is missing.", @"Decrypt data error.") }];
        }
        return nil;
    }
    
    NSData *decData = nil;
    try {
        if ([self cryptor] != NULL) {
            const VirgilByteArray &encryptedDataArray = [VSCByteArrayUtils convertVirgilByteArrayFromData:encryptedData];
            const VirgilByteArray &recIdArray = [VSCByteArrayUtils convertVirgilByteArrayFromData:recipientId];
            const VirgilByteArray &pKey = [VSCByteArrayUtils convertVirgilByteArrayFromData:privateKey];
            
            VirgilByteArray decrypted;
            if (keyPassword.length > 0) {
                const VirgilByteArray &pKeyPass = [VSCByteArrayUtils convertVirgilByteArrayFromString:keyPassword];
                decrypted = [self cryptor]->decryptWithKey(encryptedDataArray, recIdArray, pKey, pKeyPass);
            }
            else {
                decrypted = [self cryptor]->decryptWithKey(encryptedDataArray, recIdArray, pKey);
            }
            decData = [NSData dataWithBytes:decrypted.data() length:decrypted.size()];
            if (error) {
                *error = nil;
            }
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCCryptorErrorDomain code:-1005 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to decrypt with key. Cryptor is not initialized properly." }];
            }
            decData = nil;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during decryption with key.";
            }
            *error = [NSError errorWithDomain:kVSCCryptorErrorDomain code:-1006 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        decData = nil;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCCryptorErrorDomain code:-1007 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during decryption with key." }];
        }
        decData = nil;
    }
    return decData;
}

- (NSData *)decryptData:(NSData *)encryptedData password:(NSString *)password {
    return [self decryptData:encryptedData password:password error:nil];
}

- (NSData *)decryptData:(NSData *)encryptedData password:(NSString *)password error:(NSError **)error {
    if (encryptedData.length == 0 || password.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCCryptorErrorDomain code:-1008 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to decrypt with password: At least one of the required parameters is missing.", @"Decrypt data error.") }];
        }
        return nil;
    }
    
    NSData *decData = nil;
    try {
        if ([self cryptor] != NULL) {
            const VirgilByteArray &data = [VSCByteArrayUtils convertVirgilByteArrayFromData:encryptedData];
            const VirgilByteArray &pwd =[VSCByteArrayUtils convertVirgilByteArrayFromString:password];
            
            VirgilByteArray plain = [self cryptor]->decryptWithPassword(data, pwd);
            decData = [NSData dataWithBytes:plain.data() length:plain.size()];
            if (error) {
                *error = nil;
            }
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCCryptorErrorDomain code:-1009 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to decrypt with password. Cryptor is not initialized properly." }];
            }
            decData = nil;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during decryption with password.";
            }
            *error = [NSError errorWithDomain:kVSCCryptorErrorDomain code:-1010 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        decData = nil;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCCryptorErrorDomain code:-1011 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during decryption with password." }];
        }
        decData = nil;
    }
    
    return decData;
}

@end
