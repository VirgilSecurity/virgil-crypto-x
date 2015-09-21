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

/**
 * Returns NSData object containing the generated public key data.
 */
- (NSData *)publicKey;
/**
 * Returns NSData object containing the generated private key data. In case of non-nil password used in -initWithPassword: initializer private key data will be encrypted using given password.
 */ 
- (NSData *)privateKey;

@end
