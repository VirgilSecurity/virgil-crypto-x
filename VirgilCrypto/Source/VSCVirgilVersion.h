//
//  VSCVirgilVersion.h
//  VirgilFoundation
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

/**
 Provides information about Virgil library version.
 */
NS_SWIFT_NAME(VirgilVersion)
@interface VSCVirgilVersion : NSObject

/**
 Forbidden initializer.

 @return initialized instance
 */
- (instancetype __nonnull)init __unavailable;

/**
 Returns version number in the format MMNNPP (Major, Minor, Patch). (majorVersion() << 16) | (minorVersion() << 8) | patchVersion()

 @return version number in the format MMNNPP (Major, Minor, Patch).
 */
+ (size_t)asNumber;

/**
 Returns version number as string.

 @return version number as string.
 */
+ (NSString * __nonnull)asString;

/**
 Returns major version number.

 @return major version number.
 */
+ (NSUInteger)majorVersion;

/**
 Returns minor version number.

 @return minor version number.
 */
+ (NSUInteger)minorVersion;

/**
 Returns minor version number.

 @return minor version number.
 */
+ (NSUInteger)patchVersion;

/**
 Return version full name.
 
 If current release contains some additional tag, like rc1,
 then version full name will be different from the string returned by method asString(),
 i.e. 1.3.4-rc1, or 1.3.4-coolfeature, etc.

 @return version full name
 */
+ (NSString * __nonnull)fullName;

@end
