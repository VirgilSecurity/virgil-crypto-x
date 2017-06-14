//
//  VSCPfsEncryptedMessage.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface VSCPfsEncryptedMessage : NSObject

- (instancetype __nullable)initWithSessionIdentifier:(NSData * __nonnull)sessionIdentifier salt:(NSData * __nonnull)salt cipherText:(NSData * __nonnull)cipherText;

@property (nonatomic, readonly) NSData * __nonnull sessionIdentifier;
@property (nonatomic, readonly) NSData * __nonnull salt;
@property (nonatomic, readonly) NSData * __nonnull cipherText;

@end
