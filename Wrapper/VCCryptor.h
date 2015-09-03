//
//  VWCryptor.h
//  VirgilCrypto
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface VCCryptor : NSObject

- (instancetype)init NS_DESIGNATED_INITIALIZER;

- (NSData *)encryptData:(NSData *)plainData embedContentInfo:(NSNumber *)embedContentInfo;

- (NSData *)decryptData:(NSData *)encryptedData publicKeyId:(NSString *)publicKeyId privateKey:(NSData *)privateKey keyPassword:(NSString *)keyPassword;
- (NSData *)decryptData:(NSData *)encryptedData password:(NSString *)password;

- (void)addKeyRecepient:(NSString *)publicKeyId publicKey:(NSData *)publicKey;
- (void)removeKeyRecipient:(NSString *)publicKeyId;

- (void)addPasswordRecipient:(NSString *)password;
- (void)removePasswordRecipient:(NSString *)password;

- (void)removeAllRecipients;

- (NSData *)contentInfo;
- (void) setContentInfo:(NSData *) contentInfo;

@end
