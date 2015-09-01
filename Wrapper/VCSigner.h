//
//  VCSigner.h
//  VirgilCrypto
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

extern NSString* const kHashNameMD5;
extern NSString* const kHashNameSHA256;
extern NSString* const kHashNameSHA384;
extern NSString* const kHashNameSHA512;

@interface VCSigner : NSObject

- (instancetype)init;
- (instancetype)initWithHash:(NSString *)hash NS_DESIGNATED_INITIALIZER;

- (NSData *)signData:(NSData *)data privateKey:(NSData *)privateKey keyPassword:(NSString *)keyPassword;
- (BOOL)verifyData:(NSData *)data sign:(NSData *)sign publicKey:(NSData *)publicKey;

@end
