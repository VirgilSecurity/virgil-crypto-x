//
// Created by Yaroslav Tytarenko on 10/4/16.
// Copyright (c) 2016 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface VSCByteArrayUtils : NSObject

+ (NSString *)hexStringFromData:(NSData *)string;
+ (NSData *)dataFromHexString:(NSString *)string;

@end