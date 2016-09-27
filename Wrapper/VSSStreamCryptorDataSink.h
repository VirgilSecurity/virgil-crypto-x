//
// Created by Yaroslav Tytarenko on 9/26/16.
// Copyright (c) 2016 VirgilSecurity. All rights reserved.
//

#ifndef VIRGILCYPTO_VSSSTREAMCRYPTORDATASINK_H
#define VIRGILCYPTO_VSSSTREAMCRYPTORDATASINK_H

#import <Foundation/Foundation.h>
#import <VirgilCrypto/virgil/crypto/VirgilDataSink.h>


class VSSStreamCryptorDataSink : public virgil::crypto::VirgilDataSink {

    NSOutputStream *ostream;
public:
    VSSStreamCryptorDataSink(NSOutputStream *os);

    ~VSSStreamCryptorDataSink();
    bool isGood();

    void write(const VirgilByteArray& data);
};


#endif //VIRGILCYPTO_VSSSTREAMCRYPTORDATASINK_H
