//
// Created by Yaroslav Tytarenko on 10/5/16.
// Copyright (c) 2016 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>


typedef NS_ENUM(NSInteger, VSCAlgorithm) {
    VSCAlgorithmMD5,    ///< Hash Algorithm: MD5
    VSCAlgorithmSHA1,   ///< Hash Algorithm: SHA1
    VSCAlgorithmSHA224, ///< Hash Algorithm: SHA224
    VSCAlgorithmSHA256, ///< Hash Algorithm: SHA256
    VSCAlgorithmSHA384, ///< Hash Algorithm: SHA384
    VSCAlgorithmSHA512  ///< Hash Algorithm: SHA512
};


@interface VSCHash : NSObject

- (instancetype)initWithAlgorithm:(VSCAlgorithm)algorithm;

- (NSData *)hash:(NSData *)data;

@end
