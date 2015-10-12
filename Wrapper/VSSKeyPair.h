//
//  VSSKeyPair.h
//  VirgilCrypto
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface VSSKeyPair : NSObject

- (instancetype __nonnull)init;
- (instancetype __nonnull)initWithPassword:(NSString * __nullable)password NS_DESIGNATED_INITIALIZER;

/**
 * Returns NSData object containing the generated public key data.
 */
- (NSData * __nonnull)publicKey;
/**
 * Returns NSData object containing the generated private key data. In case of non-nil password used in -initWithPassword: initializer private key data will be encrypted using given password.
 */ 
- (NSData * __nonnull)privateKey;

@end
