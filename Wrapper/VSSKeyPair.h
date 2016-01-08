//
//  VSSKeyPair.h
//  VirgilFoundation
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface VSSKeyPair : NSObject

- (instancetype __nonnull)init;
- (instancetype __nonnull)initWithPassword:(NSString * __nullable)password NS_DESIGNATED_INITIALIZER;

- (instancetype __nonnull)initECNist192WithPassword:(NSString * __nullable)password;
- (instancetype __nonnull)initECNist224WithPassword:(NSString * __nullable)password;
- (instancetype __nonnull)initECNist256WithPassword:(NSString * __nullable)password;
- (instancetype __nonnull)initECNist384WithPassword:(NSString * __nullable)password;
- (instancetype __nonnull)initECNist521WithPassword:(NSString * __nullable)password;
- (instancetype __nonnull)initECBrainpool256WithPassword:(NSString * __nullable)password;
- (instancetype __nonnull)initECBrainpool384WithPassword:(NSString * __nullable)password;
- (instancetype __nonnull)initECBrainpool512WithPassword:(NSString * __nullable)password;
- (instancetype __nonnull)initECKoblitz192WithPassword:(NSString * __nullable)password;
- (instancetype __nonnull)initECKoblitz224WithPassword:(NSString * __nullable)password;
- (instancetype __nonnull)initECKoblitz256WithPassword:(NSString * __nullable)password;
- (instancetype __nonnull)initRSA256WithPassword:(NSString * __nullable)password;
- (instancetype __nonnull)initRSA512WithPassword:(NSString * __nullable)password;
- (instancetype __nonnull)initRSA1024WithPassword:(NSString * __nullable)password;
- (instancetype __nonnull)initRSA2048WithPassword:(NSString * __nullable)password;
- (instancetype __nonnull)initRSA4096WithPassword:(NSString * __nullable)password;

/**
 * Returns NSData object containing the generated public key data.
 */
- (NSData * __nonnull)publicKey;
/**
 * Returns NSData object containing the generated private key data. In case of non-nil password used in -initWithPassword: initializer private key data will be encrypted using given password.
 */ 
- (NSData * __nonnull)privateKey;

@end
