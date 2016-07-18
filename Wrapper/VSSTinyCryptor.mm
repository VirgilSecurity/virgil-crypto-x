//
//  VSSTinyCryptor.m
//  VirgilCypto
//
//  Created by Pavel Gorb on 7/12/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import "VSSTinyCryptor.h"
#import <VirgilCrypto/virgil/crypto/VirgilTinyCipher.h>

using namespace virgil::crypto;

NSString * const kVSSTinyCryptorErrorDomain = @"TinyCryptorErrorDomain";

@interface VSSTinyCryptor ()

@property (nonatomic, assign, readwrite) size_t packageSize;
@property (nonatomic, assign) VirgilTinyCipher *tinyCipher;

@end

@implementation VSSTinyCryptor

@synthesize packageSize = _packageSize;
@synthesize tinyCipher = _tinyCipher;

- (instancetype)initWithPackageSize:(VSSPackageSize)packageSize {
    self = [super init];
    if (self == nil) {
        return nil;
    }
    
    try {
        _tinyCipher = new VirgilTinyCipher(packageSize);
        _packageSize = packageSize;
    }
    catch(...) {
        _tinyCipher = NULL;
    }
    return self;
}

- (instancetype) init {
    return [self initWithPackageSize:VSSShortSMSPackageSize];
}

- (void) dealloc {
    if (_tinyCipher != NULL) {
        delete _tinyCipher;
        _tinyCipher = NULL;
    }
}

- (BOOL)resetWithError:(NSError **)error {
    BOOL ok = NO;
    try {
        if (self.tinyCipher != NULL) {
            self.tinyCipher->reset();
            if (error) {
                *error = nil;
            }
            ok = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1001 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Unable to reset Tiny Cryptor. Tiny Cryptor object is not initialized properly.", @"Unable to reset Tiny Cryptor. Tiny Cryptor object is not initialized properly.")}];
            }
        }
    }
    catch (std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = NSLocalizedString(@"Unknown error: impossible to get Tiny Cryptor exception description.", @"Unknown error: impossible to get Tiny Cryptor exception description.");
            }
            *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1002 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        ok = NO;
    }
    catch (...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1003 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Unknown Tiny Cryptor error.", @"Unknown Tiny Cryptor error.") }];
        }
        ok = NO;
    }
    return ok;
}

- (BOOL)encryptData:(NSData *)data recipientPublicKey:(NSData *)recipientKey error:(NSError **)error {
    if (data.length == 0 || recipientKey.length == 0) {
        // Can't encrypt.
        if (error) {
            *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1004 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to encrypt: Required parameter is missing.", @"Encrypt data error.") }];
        }
        return NO;
    }
    
    BOOL success = NO;
    try {
        if (self.tinyCipher != NULL) {
            // Convert NSData to VirgilByteArray
            const unsigned char *dataToEncrypt = static_cast<const unsigned char *>([data bytes]);
            VirgilByteArray plainDataArray = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(dataToEncrypt, [data length]);
            
            // Convert NSData to VirgilByteArray
            const unsigned char *pKeyData = static_cast<const unsigned char *>([recipientKey bytes]);
            VirgilByteArray keyDataArray = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pKeyData, [recipientKey length]);
            
            // Encrypt data.
            self.tinyCipher->encrypt(plainDataArray, keyDataArray);
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1005 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to encrypt. Tiny Cryptor is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during encryption.";
            }
            *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1006 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1007 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during encryption." }];
        }
        success = NO;
    }
    
    return success;
}

- (BOOL)encryptAndSignData:(NSData *)data recipientPublicKey:(NSData *)recipientKey senderPrivateKey:(NSData *)senderKey senderKeyPassword:(NSString *)keyPassword error:(NSError **)error {
    if (data.length == 0 || recipientKey.length == 0 || senderKey.length == 0) {
        // Can't encrypt.
        if (error) {
            *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1008 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to encrypt: Required parameter is missing.", @"Encrypt data error.") }];
        }
        return NO;
    }
    
    BOOL success = NO;
    try {
        if (self.tinyCipher != NULL) {
            // Convert NSData to VirgilByteArray
            const unsigned char *dataToEncrypt = static_cast<const unsigned char *>([data bytes]);
            VirgilByteArray plainDataArray = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(dataToEncrypt, [data length]);
            
            // Convert NSData to VirgilByteArray
            const unsigned char *keyData = static_cast<const unsigned char *>([recipientKey bytes]);
            VirgilByteArray keyDataArray = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(keyData, [recipientKey length]);
            
            // Convert NSData to VirgilByteArray
            const unsigned char *senderKeyData = static_cast<const unsigned char *>([senderKey bytes]);
            VirgilByteArray senderKeyDataArray = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(senderKeyData, [senderKey length]);
            
            if (keyPassword.length > 0) {
                std::string pKeyPassS = std::string([keyPassword UTF8String]);
                VirgilByteArray pKeyPassword = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pKeyPassS.data(), pKeyPassS.size());
                self.tinyCipher->encryptAndSign(plainDataArray, keyDataArray, senderKeyDataArray, pKeyPassword);
            }
            else {
                self.tinyCipher->encryptAndSign(plainDataArray, keyDataArray, senderKeyDataArray);
            }
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1009 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to encrypt. Tiny Cryptor is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during encryption.";
            }
            *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1010 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1011 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during encryption." }];
        }
        success = NO;
    }
    
    return success;
}

- (size_t)packageCount {
    size_t count = 0;
    try {
        if (self.tinyCipher != NULL) {
            count = self.tinyCipher->getPackageCount();
        }
        else {
            count = 0;
        }
    }
    catch(...) {
        count = 0;
    }
    return count;
}

- (NSData *)packageAtIndex:(size_t)index error:(NSError **)error {
    NSData *package = nil;
    try {
        if (self.tinyCipher != NULL) {
            VirgilByteArray pkArray = self.tinyCipher->getPackage(index);
            package = [NSData dataWithBytes:pkArray.data() length:pkArray.size()];
            if (error) {
                *error = nil;
            }
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1012 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to get package. Tiny Cryptor is not initialized properly." }];
            }
            package = nil;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during encryption.";
            }
            *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1013 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        package = nil;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1014 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during getting package." }];
        }
        package = nil;
    }
    
    return package;
}

- (BOOL)addPackage:(NSData *)package error:(NSError **)error {
    if (package.length == 0) {
        // Can't add package.
        if (error) {
            *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1015 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to add package: Required parameter is missing.", @"Encrypt data error.") }];
        }
        return NO;
    }
    
    BOOL ok = NO;
    try {
        if (self.tinyCipher != NULL) {
            // Convert NSData to VirgilByteArray
            const unsigned char *data = static_cast<const unsigned char *>([package bytes]);
            VirgilByteArray dataArray = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(data, [package length]);
            
            self.tinyCipher->addPackage(dataArray);
            if (error) {
                *error = nil;
            }
            ok = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1016 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Unable to add package to Tiny Cryptor. Tiny Cryptor object is not initialized properly.", @"Unable to add package to Tiny Cryptor. Tiny Cryptor object is not initialized properly.")}];
            }
        }
    }
    catch (std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = NSLocalizedString(@"Unknown error: impossible to get Tiny Cryptor exception description.", @"Unknown error: impossible to get Tiny Cryptor exception description.");
            }
            *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1017 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        ok = NO;
    }
    catch (...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1018 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Unknown Tiny Cryptor error.", @"Unknown Tiny Cryptor error.") }];
        }
        ok = NO;
    }
    return ok;
}

- (BOOL)packagesAccumulated {
    BOOL success = NO;
    try {
        if (self.tinyCipher != NULL) {
            bool ok = self.tinyCipher->isPackagesAccumulated();
            success = ok ? YES : NO;
        }
        else {
            success = NO;
        }
    }
    catch(...) {
        success = NO;
    }
    return success;
}

- (NSData *)decryptWithRecipientPrivateKey:(NSData *)recipientKey recipientKeyPassword:(NSString *)keyPassword error:(NSError **)error {
    if (recipientKey.length == 0) {
        // Can't decrypt.
        if (error) {
            *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1019 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to decrypt: Required parameter is missing.", @"Encrypt data error.") }];
        }
        return nil;
    }
    
    NSData *decrypted = nil;
    try {
        if (self.tinyCipher != NULL) {
            // Convert NSData to VirgilByteArray
            const unsigned char *keyData = static_cast<const unsigned char *>([recipientKey bytes]);
            VirgilByteArray keyDataArray = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(keyData, [recipientKey length]);
            
            VirgilByteArray decryptedArray;
            if (keyPassword.length > 0) {
                std::string pKeyPassS = std::string([keyPassword UTF8String]);
                VirgilByteArray pKeyPassword = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pKeyPassS.data(), pKeyPassS.size());
                decryptedArray = self.tinyCipher->decrypt(keyDataArray, pKeyPassword);
            }
            else {
                decryptedArray = self.tinyCipher->decrypt(keyDataArray);
            }
            if (error) {
                *error = nil;
            }
            decrypted = [NSData dataWithBytes:decryptedArray.data() length:decryptedArray.size()];
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1020 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to decrypt. Tiny Cryptor is not initialized properly." }];
            }
            decrypted = nil;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during decryption.";
            }
            *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1021 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        decrypted = nil;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1022 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during decryption." }];
        }
        decrypted = nil;
    }
    
    return decrypted;
}

- (NSData *)verifyAndDecryptWithSenderPublicKey:(NSData *)senderKey recipientPrivateKey:(NSData *)recipientKey recipientKeyPassword:(NSString *)keyPassword error:(NSError **)error {
    if (senderKey.length == 0 || recipientKey.length == 0) {
        // Can't decrypt.
        if (error) {
            *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1023 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to decrypt: Required parameter is missing.", @"Encrypt data error.") }];
        }
        return nil;
    }
    
    NSData *decrypted = nil;
    try {
        if (self.tinyCipher != NULL) {
            // Convert NSData to VirgilByteArray
            const unsigned char *senderKeyData = static_cast<const unsigned char *>([senderKey bytes]);
            VirgilByteArray senderKeyDataArray = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(senderKeyData, [senderKey length]);
            
            // Convert NSData to VirgilByteArray
            const unsigned char *keyData = static_cast<const unsigned char *>([recipientKey bytes]);
            VirgilByteArray keyDataArray = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(keyData, [recipientKey length]);
            
            VirgilByteArray decryptedArray;
            if (keyPassword.length > 0) {
                std::string pKeyPassS = std::string([keyPassword UTF8String]);
                VirgilByteArray pKeyPassword = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pKeyPassS.data(), pKeyPassS.size());
                decryptedArray = self.tinyCipher->verifyAndDecrypt(senderKeyDataArray, keyDataArray, pKeyPassword);
            }
            else {
                decryptedArray = self.tinyCipher->verifyAndDecrypt(senderKeyDataArray, keyDataArray);
            }
            if (error) {
                *error = nil;
            }
            decrypted = [NSData dataWithBytes:decryptedArray.data() length:decryptedArray.size()];
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1024 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to decrypt. Tiny Cryptor is not initialized properly." }];
            }
            decrypted = nil;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during decryption.";
            }
            *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1025 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        decrypted = nil;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSSTinyCryptorErrorDomain code:-1026 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during decryption." }];
        }
        decrypted = nil;
    }
    
    return decrypted;
}

@end
