//
// Created by Yaroslav Tytarenko on 9/26/16.
// Copyright (c) 2016 VirgilSecurity. All rights reserved.
//

#ifndef VIRGILCYPTO_VSSSTREAMCRYPTORDATASOURCE_H
#define VIRGILCYPTO_VSSSTREAMCRYPTORDATASOURCE_H

#import <Foundation/Foundation.h>
#import <VirgilCrypto/virgil/crypto/VirgilDataSource.h>

using virgil::crypto::VirgilByteArray;

class VSSStreamCryptorDataSource : public ::virgil::crypto::VirgilDataSource {

    NSInputStream *istream;
public:
    VSSStreamCryptorDataSource(NSInputStream *is);

    ~VSSStreamCryptorDataSource();

    bool hasData();

    VirgilByteArray read();
};


#endif //VIRGILCYPTO_VSSSTREAMCRYPTORDATASOURCE_H
