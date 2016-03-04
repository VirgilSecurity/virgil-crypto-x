//
//  VSSVirgilVersion.h
//  VirgilFoundation
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface VSSVirgilVersion : NSObject

/**
 * @return Returns string version of the low-level virgil cryptographic library. E.g. @"1.0.0"
 */
- (NSString * __nonnull)versionString;

/**
 * @brief Returns numeric representation of the low-level virgil cryptographic library: (major << 16) | (minor << 8) | patch.
 */
- (size_t)version;

/**
 * @brief Returns numeric representation of the major version of low-level virgil cryptographic library.
 */
- (size_t)majorVersion;

/**
 * @brief Returns numeric representation of the minor version of low-level virgil cryptographic library.
 */
- (size_t)minorVersion;

/**
 * @brief Returns numeric representation of the patch version low-level virgil cryptographic library.
 */
- (size_t)patchVersion;

@end
