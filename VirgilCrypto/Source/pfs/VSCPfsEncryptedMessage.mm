//
//  VSCPfsEncryptedMessage.mm
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSCPfsEncryptedMessage.h"
#import "VSCPfsEncryptedMessagePrivate.h"
#import "VSCByteArrayUtilsPrivate.h"
#import <VSCCrypto/VirgilCrypto.h>

using virgil::crypto::VirgilByteArray;

@implementation VSCPfsEncryptedMessage

- (instancetype)initWithEncryptedMessage:(const VirgilPFSEncryptedMessage &)encryptedMessage {
    self = [super init];
    if (self) {
        try {
            _cppPfsEncryptedMessage = new VirgilPFSEncryptedMessage(encryptedMessage);
        }
        catch(...) {
            return nil;
        }
    }
    
    return self;
}

- (instancetype)initWithSessionIdentifier:(NSData *)sessionIdentifier salt:(NSData *)salt cipherText:(NSData *)cipherText {
    self = [super init];
    if (self) {
        try {
            const VirgilByteArray &sessionIdentifierArr = [VSCByteArrayUtils convertVirgilByteArrayFromData:sessionIdentifier];
            const VirgilByteArray &saltArr = [VSCByteArrayUtils convertVirgilByteArrayFromData:salt];
            const VirgilByteArray &cipherTextArr = [VSCByteArrayUtils convertVirgilByteArrayFromData:cipherText];
            _cppPfsEncryptedMessage = new VirgilPFSEncryptedMessage(sessionIdentifierArr, saltArr, cipherTextArr);
        }
        catch(...) {
            return nil;
        }
    }
    
    return self;
}

- (NSData *)sessionIdentifier {
    const VirgilByteArray &sessionIdentifierArr = self.cppPfsEncryptedMessage->getSessionIdentifier();
    return [NSData dataWithBytes:sessionIdentifierArr.data() length:sessionIdentifierArr.size()];
}

- (NSData *)salt {
    const VirgilByteArray &saltArr = self.cppPfsEncryptedMessage->getSalt();
    return [NSData dataWithBytes:saltArr.data() length:saltArr.size()];
}

- (NSData *)cipherText {
    const VirgilByteArray &cipherTextArr = self.cppPfsEncryptedMessage->getCipherText();
    return [NSData dataWithBytes:cipherTextArr.data() length:cipherTextArr.size()];
}

- (void)dealloc {
    delete self.cppPfsEncryptedMessage;
}

@end
