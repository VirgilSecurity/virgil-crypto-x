//
//  VSCPfsSession.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface VSCPfsSession : NSObject

- (instancetype __nullable)initWithIdentifier:(NSData * __nonnull)identifier encryptionSecretKey:(NSData * __nonnull)encryptionSecretKey decryptionSecretKey:(NSData * __nonnull)decryptionSecretKey additionalData:(NSData * __nonnull)additionalData;

@property (nonatomic) BOOL isEmpty;
@property (nonatomic, readonly) NSData * __nonnull identifier;
@property (nonatomic, readonly) NSData * __nonnull encryptionSecretKey;
@property (nonatomic, readonly) NSData * __nonnull decryptionSecretKey;
@property (nonatomic, readonly) NSData * __nonnull additionalData;

@end
