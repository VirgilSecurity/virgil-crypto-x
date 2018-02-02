//
//  VSCPfsEncryptedMessage.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>

/**
 Pfs encrypted message
 */
NS_SWIFT_NAME(PfsEncryptedMessage)
@interface VSCPfsEncryptedMessage : NSObject
/**
 Designated initializer

 @param sessionIdentifier session identifier
 @param salt message salt
 @param cipherText message cipher text
 @return initialized instance
 */
- (instancetype __nullable)initWithSessionIdentifier:(NSData * __nonnull)sessionIdentifier salt:(NSData * __nonnull)salt cipherText:(NSData * __nonnull)cipherText NS_DESIGNATED_INITIALIZER;

/**
 Inherited unavailable initializer.
 
 @return initialized instance
 */
- (instancetype __nonnull)init NS_UNAVAILABLE;

/**
 Session identifier
 */
@property (nonatomic, readonly) NSData * __nonnull sessionIdentifier;

/**
 Message salt
 */
@property (nonatomic, readonly) NSData * __nonnull salt;

/**
 Message cipher text
 */
@property (nonatomic, readonly) NSData * __nonnull cipherText;

@end
