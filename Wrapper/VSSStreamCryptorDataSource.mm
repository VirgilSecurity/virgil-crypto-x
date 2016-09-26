//
// Created by Yaroslav Tytarenko on 9/26/16.
// Copyright (c) 2016 VirgilSecurity. All rights reserved.
//

#import <VirgilCrypto/virgil/crypto/VirgilStreamCipher.h>
#import "VSSStreamCryptor.h"
#include "VSSStreamCryptorDataSource.h"

VSSStreamCryptorDataSource::VSSStreamCryptorDataSource(NSInputStream *is) {
    /// Assign pointer.
    this->istream = is;
    if ([this->istream streamStatus] == NSStreamStatusNotOpen) {
        [this->istream open];
    }
}

VSSStreamCryptorDataSource::~VSSStreamCryptorDataSource() {
    /// Drop pointer.
    [this->istream close];
    this->istream = NULL;
}

bool VSSStreamCryptorDataSource::hasData() {
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

VirgilByteArray VSSStreamCryptorDataSource::read() {
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
