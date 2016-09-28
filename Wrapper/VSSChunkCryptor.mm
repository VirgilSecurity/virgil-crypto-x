//
//  VSSChunkCryptor.m
//  VirgilCypto
//
//  Created by Pavel Gorb on 3/1/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import "VSSChunkCryptor.h"
#import "VSSBaseCryptor_Private.h"
#import <VirgilCrypto/virgil/crypto/VirgilChunkCipher.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilChunkCipher;
using virgil::crypto::VirgilDataSink;
using virgil::crypto::VirgilDataSource;

NSString *const kVSSChunkCryptorErrorDomain = @"VSSChunkCryptorErrorDomain";

class VSSChunkCryptorDataSource : public VirgilDataSource {

    NSInputStream *istream;
public:
    VSSChunkCryptorDataSource(NSInputStream *is);

    ~VSSChunkCryptorDataSource();

    bool hasData();

    VirgilByteArray read();
};

VSSChunkCryptorDataSource::VSSChunkCryptorDataSource(NSInputStream *is) {
    /// Assign pointer.
    this->istream = is;
    if ([this->istream streamStatus] == NSStreamStatusNotOpen) {
        [this->istream open];
    }
}

VSSChunkCryptorDataSource::~VSSChunkCryptorDataSource() {
    /// Drop pointer.
    [this->istream close];
    this->istream = NULL;
}

bool VSSChunkCryptorDataSource::hasData() {
    if (this->istream != NULL) {
        NSStreamStatus st = [this->istream streamStatus];
        if (st == NSStreamStatusNotOpen || st == NSStreamStatusError || st == NSStreamStatusClosed) {
            return false;
        }

        if ([this->istream hasBytesAvailable]) {
            return true;
        }
    }

    return false;
}

VirgilByteArray VSSChunkCryptorDataSource::read() {
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

class VSSChunkCryptorDataSink : public VirgilDataSink {

    NSOutputStream *ostream;
public:
    VSSChunkCryptorDataSink(NSOutputStream *os);

    ~VSSChunkCryptorDataSink();
    bool isGood();

    void write(const VirgilByteArray& data);
};

VSSChunkCryptorDataSink::VSSChunkCryptorDataSink(NSOutputStream *os) {
    /// Assign pointer.
    this->ostream = os;
    if ([this->ostream streamStatus] == NSStreamStatusNotOpen) {
        [this->ostream open];
    }
}

VSSChunkCryptorDataSink::~VSSChunkCryptorDataSink() {
    /// Drop pointer.
    [this->ostream close];
    this->ostream = NULL;
}

bool VSSChunkCryptorDataSink::isGood() {
    if (this->ostream != NULL) {
        NSStreamStatus st = [this->ostream streamStatus];
        if (st == NSStreamStatusNotOpen || st == NSStreamStatusError || st == NSStreamStatusClosed) {
            return false;
        }

        if ([this->ostream hasSpaceAvailable]) {
            return true;
        }
    }

    return false;
}

void VSSChunkCryptorDataSink::write(const VirgilByteArray &data) {
    if (this->ostream != NULL) {
        [this->ostream write:data.data() maxLength:data.size()];
    }
}

@implementation VSSChunkCryptor

- (void)initializeCryptor {
    if (self.llCryptor != NULL) {
        // llCryptor has been initialized already.
        return;
    }

    try {
        self.llCryptor = new VirgilChunkCipher();
    }
    catch(...) {
        self.llCryptor = NULL;
    }
}

- (void)dealloc {
    if (self.llCryptor != NULL) {
        delete (VirgilChunkCipher *)self.llCryptor;
        self.llCryptor = NULL;
    }
}

- (VirgilChunkCipher *)cryptor {
    if (self.llCryptor == NULL) {
        return NULL;
    }

    return static_cast<VirgilChunkCipher *>(self.llCryptor);
}

- (void)encryptDataFromStream:(NSInputStream *)source toStream:(NSOutputStream *)destination preferredChunkSize:(size_t)chunkSize embedContentInfo:(BOOL)embedContentInfo error:(NSError **)error {
    if (source == nil || destination == nil) {
        if (error) {
            *error = [NSError errorWithDomain:kVSSChunkCryptorErrorDomain code:-1000 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to encrypt stream: At least one of the required parameters is missing.", @"Encrypt stream data error.") }];
        }
        return;
    }

    try {
        if ([self cryptor] != NULL) {
            VSSChunkCryptorDataSource src = VSSChunkCryptorDataSource(source);
            VSSChunkCryptorDataSink dest = VSSChunkCryptorDataSink(destination);
            [self cryptor]->encrypt(src, dest, embedContentInfo, chunkSize);

            if (error) {
                *error = nil;
            }
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSSChunkCryptorErrorDomain code:-1001 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to encrypt stream. Cryptor is not initialized properly." }];
            }
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during stream encryption.";
            }
            *error = [NSError errorWithDomain:kVSSChunkCryptorErrorDomain code:-1002 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSSChunkCryptorErrorDomain code:-1003 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during stream encryption." }];
        }
    }
}

- (void)decryptFromStream:(NSInputStream * __nonnull)source toStream:(NSOutputStream * __nonnull)destination recipientId:(NSString * __nonnull)recipientId privateKey:(NSData * __nonnull)privateKey keyPassword:(NSString * __nullable)keyPassword error:(NSError * __nullable * __nullable)error {
    if (source == nil || destination == nil || recipientId.length == 0 || privateKey.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSSChunkCryptorErrorDomain code:-1004 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to decrypt stream: At least one of the required parameters is missing.", @"Decrypt stream data error.") }];
        }
    }

    try {
        if ([self cryptor] != NULL) {
            VSSChunkCryptorDataSource src = VSSChunkCryptorDataSource(source);
            VSSChunkCryptorDataSink dest = VSSChunkCryptorDataSink(destination);
            std::string recId = std::string([recipientId UTF8String]);
            const unsigned char *pKey = static_cast<const unsigned char *>([privateKey bytes]);
            if (keyPassword.length == 0) {
                [self cryptor]->decryptWithKey(src, dest, VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(recId.data(), recId.size()), VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pKey, [privateKey length]));
            }
            else {
                std::string keyPass = std::string([keyPassword UTF8String]);
                [self cryptor]->decryptWithKey(src, dest, VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(recId.data(), recId.size()), VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pKey, [privateKey length]), VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(keyPass.data(), keyPass.size()));
            }
            if (error) {
                *error = nil;
            }
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSSChunkCryptorErrorDomain code:-1005 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to decrypt stream. Cryptor is not initialized properly." }];
            }
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during stream decryption.";
            }
            *error = [NSError errorWithDomain:kVSSChunkCryptorErrorDomain code:-1006 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSSChunkCryptorErrorDomain code:-1007 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during stream decryption." }];
        }
    }
}

- (void)decryptFromStream:(NSInputStream * __nonnull)source toStream:(NSOutputStream * __nonnull)destination password:(NSString * __nonnull)password error:(NSError * __nullable * __nullable)error {
    if (source == nil || destination == nil || password.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSSChunkCryptorErrorDomain code:-1008 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to decrypt stream: At least one of the required parameters is missing.", @"Decrypt stream data error.") }];
        }
    }

    BOOL success = NO;
    try {
        if ([self cryptor] != NULL) {
            VSSChunkCryptorDataSource src = VSSChunkCryptorDataSource(source);
            VSSChunkCryptorDataSink dest = VSSChunkCryptorDataSink(destination);
            std::string pwd = std::string([password UTF8String]);
            [self cryptor]->decryptWithPassword(src, dest, VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pwd.data(), pwd.size()));
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSSChunkCryptorErrorDomain code:-1009 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to decrypt stream. Cryptor is not initialized properly." }];
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
            *error = [NSError errorWithDomain:kVSSChunkCryptorErrorDomain code:-1010 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSSChunkCryptorErrorDomain code:-1011 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during stream decryption." }];
        }
        success = NO;
    }
}

@end
