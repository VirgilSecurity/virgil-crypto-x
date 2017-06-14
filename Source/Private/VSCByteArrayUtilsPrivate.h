//
//  VSCByteArrayUtilsPrivate.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import "VSCByteArrayUtils.h"

#import <virgil/crypto/VirgilByteArray.h>

@interface VSCByteArrayUtils()

+ (virgil::crypto::VirgilByteArray)convertVirgilByteArrayFromString:(NSString *)string;
+ (virgil::crypto::VirgilByteArray)convertVirgilByteArrayFromData:(NSData *)data;

@end
