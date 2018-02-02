//
//  VSCPfsPublicKey.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>

/**
 Class that represents public key, that is related to PFS operations.
 */
NS_SWIFT_NAME(PfsPublicKey)
@interface VSCPfsPublicKey : NSObject
/**
 Designated initializer

 @param key public key data
 @return initialized instance
 */
- (instancetype __nullable)initWithKey:(NSData * __nonnull)key NS_DESIGNATED_INITIALIZER;

/**
 Inherited unavailable initializer.
 
 @return initialized instance
 */
- (instancetype __nonnull)init NS_UNAVAILABLE;

/**
 Public key data
 */
@property (nonatomic, readonly) NSData * __nonnull key;

@end
