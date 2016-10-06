//
// Created by Yaroslav Tytarenko on 10/5/16.
// Copyright (c) 2016 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>


typedef NS_ENUM(NSInteger, VSCHashAlgorithm) {
    VSCHashAlgorithmMD5,    ///< Hash Algorithm: MD5
    VSCHashAlgorithmSHA1,   ///< Hash Algorithm: SHA1
    VSCHashAlgorithmSHA224, ///< Hash Algorithm: SHA224
    VSCHashAlgorithmSHA256, ///< Hash Algorithm: SHA256
    VSCHashAlgorithmSHA384, ///< Hash Algorithm: SHA384
    VSCHashAlgorithmSHA512  ///< Hash Algorithm: SHA512
};


@interface VSCHash : NSObject

- (instancetype)initWithAlgorithm:(VSCHashAlgorithm)algorithm;

- (NSData *)hash:(NSData *)data;

@end
