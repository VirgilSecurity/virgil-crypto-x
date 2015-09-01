//
//  VCKeyPair.h
//  VirgilCrypto
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface VCKeyPair : NSObject

- (instancetype)init;
- (instancetype)initWithPassword:(NSString *)password NS_DESIGNATED_INITIALIZER;

- (NSData *)publicKey;
- (NSData *)privateKey;

@end
