//
//  VSSVirgilVersion.h
//  VirgilFoundation
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface VSSVirgilVersion : NSObject

- (instancetype __nonnull)init NS_DESIGNATED_INITIALIZER;

/**
 * Returns string version of the low-level virgil cryptographic library. E.g. @"1.0.0"
 */
- (NSString * __nonnull)versionString;
/**
 * Returns numeric representation of the low-level virgil cryptographic library.
 */
- (NSNumber * __nonnull)version;

@end
