//
// Created by Yaroslav Tytarenko on 9/26/16.
// Copyright (c) 2016 VirgilSecurity. All rights reserved.
//

#include "VSSStreamCryptorDataSource.h"
#import "VSSStreamCryptor.h"
#include "VSSStreamCryptorDataSink.h"

VSSStreamCryptorDataSink::VSSStreamCryptorDataSink(NSOutputStream *os) {
    /// Assign pointer.
    this->ostream = os;
    if ([this->ostream streamStatus] == NSStreamStatusNotOpen) {
        [this->ostream open];
    }
}

VSSStreamCryptorDataSink::~VSSStreamCryptorDataSink() {
    /// Drop pointer.
    [this->ostream close];
    this->ostream = NULL;
}

bool VSSStreamCryptorDataSink::isGood() {
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

void VSSStreamCryptorDataSink::write(const VirgilByteArray &data) {
    if (this->ostream != NULL) {
        [this->ostream write:data.data() maxLength:data.size()];
    }
}
