//
//  VSCPfsSession.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>

/**
 Pfs session
 */
NS_SWIFT_NAME(PfsSession)
@interface VSCPfsSession : NSObject
/**
 Designated initializer.

 @param identifier session identifier
 @param encryptionSecretKey encryption symmetric AES key
 @param decryptionSecretKey decryption symmetric AES key
 @param additionalData additional data for authentication
 @return initialized instance
 */
- (instancetype __nullable)initWithIdentifier:(NSData * __nonnull)identifier encryptionSecretKey:(NSData * __nonnull)encryptionSecretKey decryptionSecretKey:(NSData * __nonnull)decryptionSecretKey additionalData:(NSData * __nonnull)additionalData NS_DESIGNATED_INITIALIZER;

/**
 Inherited unavailable initializer.
 
 @return initialized instance
 */
- (instancetype __nonnull)init NS_UNAVAILABLE;

/**
 Session identifier
 */
@property (nonatomic, readonly) NSData * __nonnull identifier;

/**
 Encryption symmetric AES key
 */
@property (nonatomic, readonly) NSData * __nonnull encryptionSecretKey;

/**
 Decryption symmetric AES key
 */
@property (nonatomic, readonly) NSData * __nonnull decryptionSecretKey;

/**
 Additional data for authentication
 */
@property (nonatomic, readonly) NSData * __nonnull additionalData;

@end
