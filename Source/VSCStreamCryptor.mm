//
//  VSCStreamCryptor.m
//  VirgilCypto
//
//  Created by Pavel Gorb on 2/25/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import "VSCStreamCryptor.h"
#import "VSCBaseCryptor_Private.h"
#import "VSCByteArrayUtils_Private.h"
#import <virgil/crypto/VirgilStreamCipher.h>
#import <virgil/crypto/VirgilDataSource.h>
#import <virgil/crypto/VirgilDataSink.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilStreamCipher;
using virgil::crypto::VirgilDataSource;
using virgil::crypto::VirgilDataSink;

NSString *const kVSCStreamCryptorErrorDomain = @"VSCStreamCryptorErrorDomain";

class VSCStreamCryptorDataSource : public ::virgil::crypto::VirgilDataSource {

    NSInputStream *istream;
public:
    VSCStreamCryptorDataSource(NSInputStream *is);

    ~VSCStreamCryptorDataSource();

    bool hasData();

    VirgilByteArray read();
};

VSCStreamCryptorDataSource::VSCStreamCryptorDataSource(NSInputStream *is) {
    /// Assign pointer.
    this->istream = is;
    if (this->istream.streamStatus == NSStreamStatusNotOpen) {
        [this->istream open];
    }
}

VSCStreamCryptorDataSource::~VSCStreamCryptorDataSource() {
    /// Drop pointer.
    [this->istream close];
    this->istream = NULL;
}

bool VSCStreamCryptorDataSource::hasData() {
    if (this->istream != NULL) {
        NSStreamStatus st = this->istream.streamStatus;
        if (st == NSStreamStatusNotOpen || st == NSStreamStatusError || st == NSStreamStatusClosed) {
            return false;
        }

        if (this->istream.hasBytesAvailable) {
            return true;
        }
    }

    return false;
}

VirgilByteArray VSCStreamCryptorDataSource::read() {
    std::vector<unsigned char> buffer;
    unsigned long desiredSize = 1024;
    long actualSize = 0;

    buffer.resize(desiredSize);
    if (this->istream != NULL) {
        actualSize = [this->istream read:buffer.data() maxLength:desiredSize];
        if (actualSize < 0) {
            actualSize = 0;
        }
    }
    buffer.resize((unsigned long) actualSize);
    buffer.shrink_to_fit();

    return static_cast<VirgilByteArray>(buffer);
}

class VSCStreamCryptorDataSink : public virgil::crypto::VirgilDataSink {

    NSOutputStream *ostream;
public:
    VSCStreamCryptorDataSink(NSOutputStream *os);

    ~VSCStreamCryptorDataSink();
    bool isGood();

    void write(const VirgilByteArray& data);
};

VSCStreamCryptorDataSink::VSCStreamCryptorDataSink(NSOutputStream *os) {
    /// Assign pointer.
    this->ostream = os;
    if (this->ostream.streamStatus == NSStreamStatusNotOpen) {
        [this->ostream open];
    }
}

VSCStreamCryptorDataSink::~VSCStreamCryptorDataSink() {
    /// Drop pointer.
    [this->ostream close];
    this->ostream = NULL;
}

bool VSCStreamCryptorDataSink::isGood() {
    if (this->ostream != NULL) {
        NSStreamStatus st = this->ostream.streamStatus;
        if (st == NSStreamStatusNotOpen || st == NSStreamStatusError || st == NSStreamStatusClosed) {
            return false;
        }

        if (this->ostream.hasSpaceAvailable) {
            return true;
        }
    }

    return false;
}

void VSCStreamCryptorDataSink::write(const VirgilByteArray &data) {
    if (this->ostream != NULL) {
        [this->ostream write:data.data() maxLength:data.size()];
    }
}

@interface VSCStreamCryptor ()

@end

@implementation VSCStreamCryptor

- (void)initializeCryptor {
    if (self.llCryptor != NULL) {
        // llCryptor has been initialized already.
        return;
    }
    
    try {
        self.llCryptor = new VirgilStreamCipher();
    }
    catch(...) {
        self.llCryptor = NULL;
    }
}

- (void)dealloc {
    if (self.llCryptor != NULL) {
        delete (VirgilStreamCipher *)self.llCryptor;
        self.llCryptor = NULL;
    }
}

- (VirgilStreamCipher *)cryptor {
    if (self.llCryptor == NULL) {
        return NULL;
    }
    
    return static_cast<VirgilStreamCipher *>(self.llCryptor);
}

- (BOOL)encryptDataFromStream:(NSInputStream *)source toStream:(NSOutputStream *)destination embedContentInfo:(BOOL)embedContentInfo error:(NSError **)error {
    if (source == nil || destination == nil) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCStreamCryptorErrorDomain code:-1000 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to encrypt stream: At least one of the required parameters is missing.", @"Encrypt stream data error.") }];
        }
        return NO;
    }
    
    BOOL success = NO;
    try {
        if ([self cryptor] != NULL) {
            VSCStreamCryptorDataSource src = VSCStreamCryptorDataSource(source);
            VSCStreamCryptorDataSink dest = VSCStreamCryptorDataSink(destination);
            bool embed = embedContentInfo;
            [self cryptor]->encrypt(src, dest, embed);

            if (error) {
                *error = nil;
            }

            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCStreamCryptorErrorDomain code:-1001 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to encrypt stream. Cryptor is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during stream encryption.";
            }
            *error = [NSError errorWithDomain:kVSCStreamCryptorErrorDomain code:-1002 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCStreamCryptorErrorDomain code:-1003 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during stream encryption." }];
        }
        success = NO;
    }
    return success;
}

- (BOOL)decryptFromStream:(NSInputStream * __nonnull)source toStream:(NSOutputStream * __nonnull)destination recipientId:(NSData * __nonnull)recipientId privateKey:(NSData * __nonnull)privateKey keyPassword:(NSString * __nullable)keyPassword error:(NSError * __nullable * __nullable)error {
    if (source == nil || destination == nil || recipientId.length == 0 || privateKey.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCStreamCryptorErrorDomain code:-1004 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to decrypt stream: At least one of the required parameters is missing.", @"Decrypt stream data error.") }];
        }
        return NO;
    }
    
    BOOL success = NO;
    try {
        if ([self cryptor] != NULL) {
            VSCStreamCryptorDataSource src = VSCStreamCryptorDataSource(source);
            VSCStreamCryptorDataSink dest = VSCStreamCryptorDataSink(destination);
            const VirgilByteArray &recId = [VSCByteArrayUtils convertVirgilByteArrayFromData:recipientId];
            const VirgilByteArray &pKey = [VSCByteArrayUtils convertVirgilByteArrayFromData:privateKey];

            if (keyPassword.length == 0) {
                [self cryptor]->decryptWithKey(src, dest, recId, pKey);
            }
            else {
                const VirgilByteArray &keyPass = [VSCByteArrayUtils convertVirgilByteArrayFromString:keyPassword];
                [self cryptor]->decryptWithKey(src, dest, recId, pKey, keyPass);
            }
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCStreamCryptorErrorDomain code:-1005 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to decrypt stream. Cryptor is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during stream decryption.";
            }
            *error = [NSError errorWithDomain:kVSCStreamCryptorErrorDomain code:-1006 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCStreamCryptorErrorDomain code:-1007 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during stream decryption." }];
        }
        success = NO;
    }
    return success;
}

- (BOOL)decryptFromStream:(NSInputStream * __nonnull)source toStream:(NSOutputStream * __nonnull)destination password:(NSString * __nonnull)password error:(NSError * __nullable * __nullable)error {
    if (source == nil || destination == nil || password.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCStreamCryptorErrorDomain code:-1008 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to decrypt stream: At least one of the required parameters is missing.", @"Decrypt stream data error.") }];
        }
        return NO;
    }
    
    BOOL success = NO;
    try {
        if ([self cryptor] != NULL) {
            VSCStreamCryptorDataSource src = VSCStreamCryptorDataSource(source);
            VSCStreamCryptorDataSink dest = VSCStreamCryptorDataSink(destination);
            const VirgilByteArray &pwd = [VSCByteArrayUtils convertVirgilByteArrayFromString:password];

            [self cryptor]->decryptWithPassword(src, dest,pwd);

            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCStreamCryptorErrorDomain code:-1009 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to decrypt stream. Cryptor is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during stream decryption.";
            }
            *error = [NSError errorWithDomain:kVSCStreamCryptorErrorDomain code:-1010 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCStreamCryptorErrorDomain code:-1011 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during stream decryption." }];
        }
        success = NO;
    }
    return success;
}

@end
