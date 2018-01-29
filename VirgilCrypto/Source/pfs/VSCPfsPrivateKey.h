//
//  VSCPfsPrivateKey.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface VSCPfsPrivateKey : NSObject

- (instancetype __nullable)initWithKey:(NSData * __nonnull)key password:(NSData * __nullable)password;

- (instancetype __nonnull)init NS_UNAVAILABLE;

@property (nonatomic, readonly) BOOL isEmpty;
@property (nonatomic, readonly) NSData * __nonnull key;
@property (nonatomic, readonly) NSData * __nullable password;

@end
