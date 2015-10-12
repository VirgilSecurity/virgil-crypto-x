//
//  VSSCryptor.mm
//  VirgilCrypto
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import "VSSCryptor.h"
#import <VirgilSecurity/virgil/crypto/VirgilCipher.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilCipher;

@interface VSSCryptor ()

@property (nonatomic, assign) VirgilCipher * __nullable cipher;

- (VirgilCipher * __nullable)createCipher;

@end

@implementation VSSCryptor

@synthesize cipher = _cipher;

#pragma mark - Lifecycle

- (instancetype)init {
    self = [super init];
    if (self == nil) {
        return nil;
    }
    
    _cipher = [self createCipher];
    return self;
}

- (void)dealloc {
    if (_cipher != NULL) {
        delete(_cipher);
        _cipher = NULL;
    }
}

- (VirgilCipher *)createCipher {
    VirgilCipher *cipher = NULL;
    @try {
        cipher = new VirgilCipher();
    }
    @catch(NSException *exc) {
        NSLog(@"Error creating VirgilCipher object: %@, %@", [exc name], [exc reason]);
        cipher = NULL;
    }
    @finally {
        return cipher;
    }
}

#pragma mark - Public class logic

- (NSData *)encryptData:(NSData *)plainData embedContentInfo:(NSNumber *) embedContentInfo {
    if (plainData.length == 0) {
        // Can't encrypt.
        return nil;
    }
    
    NSData *encData = nil;
    if (self.cipher != NULL) {
        @try {
            // Convert NSData to
            const char *dataToEncrypt = (const char *)[plainData bytes];
            VirgilByteArray plainDataArray = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(dataToEncrypt, [plainData length]);
            
            // Encrypt data.
            VirgilByteArray encryptedData = ((VirgilCipher *)self.cipher)->encrypt(plainDataArray, (bool)[embedContentInfo boolValue]);
            encData = [NSData dataWithBytes:encryptedData.data() length:encryptedData.size()];
        }
        @catch(NSException *exc) {
            NSLog(@"Error encrypting data: %@, %@", [exc name], [exc reason]);
            encData = nil;
        }
        @finally {
            return encData;
        }
    }
    return encData;
}

- (NSData *)decryptData:(NSData *)encryptedData publicKeyId:(NSString *)publicKeyId privateKey:(NSData *)privateKey keyPassword:(NSString *)keyPassword {
    if (encryptedData.length == 0 || publicKeyId.length == 0 || privateKey.length == 0) {
        // Can't decrypt
        return nil;
    }
    
    NSData *decData = nil;
    if (self.cipher != NULL) {
        @try {
            const char *dataToDecrypt = (const char *)[encryptedData bytes];
            VirgilByteArray encryptedDataArray = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(dataToDecrypt, [encryptedData length]);
            
            std::string certId = std::string([publicKeyId UTF8String]);
            VirgilByteArray certIdArray = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(certId.data(), certId.size());
            
            const char *pKeyData = (const char *)[privateKey bytes];
            VirgilByteArray pKey = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pKeyData, [privateKey length]);
            
            VirgilByteArray decrypted;
            if (keyPassword.length > 0) {
                std::string pKeyPassS = std::string([keyPassword UTF8String]);
                VirgilByteArray pKeyPass = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pKeyPassS.data(), pKeyPassS.size());
                decrypted = ((VirgilCipher *)self.cipher)->decryptWithKey(encryptedDataArray, certIdArray, pKey, pKeyPass);
            }
            else {
                decrypted = ((VirgilCipher *)self.cipher)->decryptWithKey(encryptedDataArray, certIdArray, pKey);
            }
            decData = [NSData dataWithBytes:decrypted.data() length:decrypted.size()];
        }
        @catch(NSException *exc) {
            NSLog(@"Error decrypting data with key: %@, %@", [exc name], [exc reason]);
            decData = nil;
        }
        @finally {
            return decData;
        }
    }
    return decData;
}

- (NSData *)decryptData:(NSData *)encryptedData password:(NSString *)password {
    if (encryptedData.length == 0 || password.length == 0) {
        return nil;
    }
    
    NSData *decData = nil;
    if (self.cipher != NULL) {
        @try {
            const char *dataToDecrypt = (const char*)[encryptedData bytes];
            VirgilByteArray data = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(dataToDecrypt, [encryptedData length]);
            
            std::string pass = std::string([password UTF8String]);
            VirgilByteArray pwd = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pass.data(), pass.size());
            
            VirgilByteArray plain = ((VirgilCipher *)self.cipher)->decryptWithPassword(data, pwd);
            decData = [NSData dataWithBytes:plain.data() length:plain.size()];
        }
        @catch(NSException *exc) {
            NSLog(@"Error decrypting data with password: %@, %@", [exc name], [exc reason]);
            decData = nil;
        }
        @finally {
            return decData;
        }
    }
    
    return decData;
}

- (void)addKeyRecepient:(NSString *)publicKeyId publicKey:(NSData *)publicKey {
    if (publicKeyId.length == 0 || publicKey.length == 0) {
        // Can't add recipient.
        return;
    }
    
    if (self.cipher != NULL) {
        @try {
            std::string certId = std::string([publicKeyId UTF8String]);
            VirgilByteArray certIdArray = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(certId.data(), certId.size());
            
            const char *pKeyBytes = (const char *)[publicKey bytes];
            VirgilByteArray pKeyArray = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pKeyBytes, [publicKey length]);
            
            self.cipher->addKeyRecipient(certIdArray, pKeyArray);
        }
        @catch(NSException *exc) {
            NSLog(@"Error adding Key Recepient object: %@, %@", [exc name], [exc reason]);
        }
    }
}

- (void)removeKeyRecipient:(NSString *)publicKeyId {
    if (publicKeyId.length == 0) {
        // Can't remove recipient
        return;
    }
    
    if (self.cipher != NULL) {
        @try {
            std::string certId = std::string([publicKeyId UTF8String]);
            VirgilByteArray certIdArray = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(certId.data(), certId.size());
            
            self.cipher->removeKeyRecipient(certIdArray);
        }
        @catch(NSException *exc) {
            NSLog(@"Error removing Key Recepient object: %@, %@", [exc name], [exc reason]);
        }
    }
}

- (void)addPasswordRecipient:(NSString *)password {
    if (password.length == 0) {
        return;
    }
    
    if (self.cipher != NULL) {
        @try {
            std::string pass = std::string([password UTF8String]);
            VirgilByteArray passArray = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pass.data(), pass.size());
            
            self.cipher->addPasswordRecipient(passArray);
        }
        @catch(NSException *exc) {
            NSLog(@"Error adding Password Recepient object: %@, %@", [exc name], [exc reason]);
        }
    }
}

- (void)removePasswordRecipient:(NSString *)password {
    if (password.length == 0) {
        return;
    }
    
    if (self.cipher != NULL) {
        @try {
            std::string pass = std::string([password UTF8String]);
            VirgilByteArray passArray = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pass.data(), pass.size());
            
            self.cipher->removePasswordRecipient(passArray);
        }
        @catch(NSException *exc) {
            NSLog(@"Error removing Password Recepient object: %@, %@", [exc name], [exc reason]);
        }
    }
}

- (void)removeAllRecipients {
    if (self.cipher != NULL) {
        @try {
            self.cipher->removeAllRecipients();
        }
        @catch(NSException *exc) {
            NSLog(@"Error removing all Recepient objects: %@, %@", [exc name], [exc reason]);
        }
    }
}

- (NSData *)contentInfo {
    NSData* contentInfo = nil;
    if (self.cipher != NULL) {
        @try {
            VirgilByteArray content = self.cipher->getContentInfo();
            contentInfo = [NSData dataWithBytes:content.data() length:content.size()];
        }
        @catch(NSException *exc) {
            NSLog(@"Error getting Content Info object: %@, %@", [exc name], [exc reason]);
            contentInfo = nil;
        }
        @finally {
            return contentInfo;
        }
    }
    return contentInfo;
}

- (void) setContentInfo:(NSData *) contentInfo {
    if (self.cipher != NULL) {
        @try {
            const char *contentInfoBytes = (const char *)[contentInfo bytes];
            VirgilByteArray contentInfoArray = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(contentInfoBytes, [contentInfo length]);
            self.cipher->setContentInfo(contentInfoArray);
        }
        @catch(NSException *exc) {
            NSLog(@"Error setting Content Info object: %@, %@", [exc name], [exc reason]);
        }
    }
}

@end
