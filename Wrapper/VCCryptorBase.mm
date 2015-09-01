//
//  VWCryptorBase.mm
//  VirgilCrypto
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import "VCCryptorBase.h"
#import "VCCryptorBase_Private.h"

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilCipherBase;

@implementation VCCryptorBase

@synthesize cipher = _cipher;

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

- (VirgilCipherBase *)createCipher {
    return NULL;
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
