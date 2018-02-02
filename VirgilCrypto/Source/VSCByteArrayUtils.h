//
// Created by Yaroslav Tytarenko on 10/4/16.
// Copyright (c) 2016 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>

/**
 Utils class for hex encoding.
 */
NS_SWIFT_NAME(ByteArrayUtils)
@interface VSCByteArrayUtils : NSObject

/**
 Encodes data into hex representation.

 @param data data to encode
 @return hex representation
 */
+ (NSString *)hexStringFromData:(NSData *)data;

/**
 Decodes data from hex representation.

 @param string hex string
 @return decoded data
 */
+ (NSData *)dataFromHexString:(NSString *)string;

@end
