//
//  VСCryptorBase.h
//  VirgilCrypto
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface VCCryptorBase : NSObject

- (instancetype)init NS_DESIGNATED_INITIALIZER;

- (void)addKeyRecepient:(NSString *)publicKeyId publicKey:(NSData *)publicKey;
- (void)removeKeyRecipient:(NSString *)publicKeyId;

- (void)addPasswordRecipient:(NSString *)password;
- (void)removePasswordRecipient:(NSString *)password;

- (void)removeAllRecipients;

- (NSData *)contentInfo;
- (void) setContentInfo:(NSData *) contentInfo;

@end
