//
// Created by Yaroslav Tytarenko on 10/5/16.
// Copyright (c) 2016 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>


typedef NS_ENUM(NSInteger, VSCAlgorithm) {
    VSCMD5,    ///< Hash Algorithm: MD5
    VSCSHA1,   ///< Hash Algorithm: SHA1
    VSCSHA224, ///< Hash Algorithm: SHA224
    VSCSHA256, ///< Hash Algorithm: SHA256
    VSCSHA384, ///< Hash Algorithm: SHA384
    VSCSHA512  ///< Hash Algorithm: SHA512
};


@interface VSCHash : NSObject

- (instancetype)initWithAlgorithm:(VSCAlgorithm)algorithm;

- (NSData *)hash:(NSData *)data;

@end
