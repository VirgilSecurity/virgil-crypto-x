//
//  VSCPfsPrivateKey.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>

/**
 Class that represents private key, that is related to PFS operations.
 */
NS_SWIFT_NAME(PfsPrivateKey)
@interface VSCPfsPrivateKey : NSObject
/**
 Designated initializer.

 @param key private key data
 @param password private key password
 @return initialized instance
 */
- (instancetype __nullable)initWithKey:(NSData * __nonnull)key password:(NSData * __nullable)password NS_DESIGNATED_INITIALIZER;

/**
 Inherited unavailable initializer.
 
 @return initialized instance
 */
- (instancetype __nonnull)init NS_UNAVAILABLE;

/**
 Private key
 */
@property (nonatomic, readonly) NSData * __nonnull key;

/**
 Private key password
 */
@property (nonatomic, readonly) NSData * __nullable password;

@end
