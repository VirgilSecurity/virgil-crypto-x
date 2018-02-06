//
// Created by Yaroslav Tytarenko on 10/4/16.
// Copyright (c) 2016 VirgilSecurity. All rights reserved.
//

#import "VSCByteArrayUtils.h"
#import "VSCByteArrayUtilsPrivate.h"
#import <VSCCrypto/VirgilCrypto.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;

@implementation VSCByteArrayUtils

+ (VirgilByteArray)convertVirgilByteArrayFromData:(NSData *)data {
    if (data.length == 0) {
        return VirgilByteArray();
    }
    
    const unsigned char *dataToEncrypt = static_cast<const unsigned char *>(data.bytes);
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(dataToEncrypt, [data length]);
}

+ (VirgilByteArray)convertVirgilByteArrayFromString:(NSString *)string {
    if (string.length == 0) {
        return VirgilByteArray();
    }
    
    std::string pass = std::string(string.UTF8String);
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pass.data(), pass.size());
}

+ (NSString *)hexStringFromData:(NSData *)data {
    std::string cStr = VirgilByteArrayUtils::bytesToHex([VSCByteArrayUtils convertVirgilByteArrayFromData:data]);
    return [NSString stringWithCString:cStr.c_str() encoding:[NSString defaultCStringEncoding]];;
}

+ (NSData *)dataFromHexString:(NSString *)string {
    std::string cStr = std::string(string.UTF8String);
    VirgilByteArray vData = VirgilByteArrayUtils::hexToBytes(cStr);
    return [[NSData alloc] initWithBytes:vData.data() length:vData.size()];
}

@end
