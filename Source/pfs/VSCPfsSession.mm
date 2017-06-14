//
//  VSCPfsSession.mn
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSCPfsSession.h"
#import "VSCPfsSessionPrivate.h"
#import "VSCByteArrayUtilsPrivate.h"

#import <virgil/crypto/VirgilByteArray.h>

using virgil::crypto::VirgilByteArray;

@implementation VSCPfsSession

- (instancetype)initWithSession:(const VirgilPFSSession &)session {
    self = [super init];
    if (self) {
        try {
            _cppPfsSession = new VirgilPFSSession(session);
        }
        catch(...) {
            return nil;
        }
    }
    
    return self;
}

- (instancetype)initWithIdentifier:(NSData *)identifier encryptionSecretKey:(NSData *)encryptionSecretKey decryptionSecretKey:(NSData *)decryptionSecretKey additionalData:(NSData *)additionalData {
    self = [super init];
    if (self) {
        try {
            const VirgilByteArray &identifierArr = [VSCByteArrayUtils convertVirgilByteArrayFromData:identifier];
            const VirgilByteArray &encryptionSecretKeyArr = [VSCByteArrayUtils convertVirgilByteArrayFromData:encryptionSecretKey];
            const VirgilByteArray &decryptionSecretKeyArr = [VSCByteArrayUtils convertVirgilByteArrayFromData:decryptionSecretKey];
            const VirgilByteArray &additionalDataArr = [VSCByteArrayUtils convertVirgilByteArrayFromData:additionalData];
            
            _cppPfsSession = new VirgilPFSSession(identifierArr, encryptionSecretKeyArr, decryptionSecretKeyArr, additionalDataArr);
        }
        catch(...) {
            return nil;
        }
    }
    
    return self;
}

- (BOOL)isEmpty {
    return self.cppPfsSession->isEmpty();
}

- (NSData *)identifier {
    const VirgilByteArray &identifierArr = self.cppPfsSession->getIdentifier();
    return [NSData dataWithBytes:identifierArr.data() length:identifierArr.size()];
}

- (NSData *)encryptionSecretKey {
    const VirgilByteArray &encryptionSecretKeyArr = self.cppPfsSession->getEncryptionSecretKey();
    return [NSData dataWithBytes:encryptionSecretKeyArr.data() length:encryptionSecretKeyArr.size()];
}

- (NSData *)decryptionSecretKey {
    const VirgilByteArray &decryptionSecretKeyArr = self.cppPfsSession->getDecryptionSecretKey();
    return [NSData dataWithBytes:decryptionSecretKeyArr.data() length:decryptionSecretKeyArr.size()];
}

- (NSData *)additionalData {
    const VirgilByteArray &additionalDataArr = self.cppPfsSession->getAdditionalData();
    return [NSData dataWithBytes:additionalDataArr.data() length:additionalDataArr.size()];
}

- (void)dealloc {
    delete self.cppPfsSession;
}

@end
