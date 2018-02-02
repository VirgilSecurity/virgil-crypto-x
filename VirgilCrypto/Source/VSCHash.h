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

/**
 Class for hashing.
 */
NS_SWIFT_NAME(Hash)
@interface VSCHash : NSObject

/**
 Initializer.

 @param algorithm hash algorithm to use
 @return initalized instance
 */
- (instancetype __nonnull)initWithAlgorithm:(VSCHashAlgorithm)algorithm;

/**
 Hashes data.

 @param data data to hash
 @return computed hash
 */
- (NSData * __nonnull)hash:(NSData * __nullable)data;

/**
 Start hashing
 */
- (void)start;

/**
 Updates hash with new data.

 @param data new data
 */
- (void)updateWithData:(NSData * __nullable)data;

/**
 Finished hashing process.

 @return computed hash.
 */
- (NSData * __nonnull)finish;

@end
