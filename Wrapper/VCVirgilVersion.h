//
//  VCVirgilVersion.h
//  VirgilCrypto
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface VCVirgilVersion : NSObject

- (instancetype)init NS_DESIGNATED_INITIALIZER;

- (NSString *)versionString;
- (NSNumber *)version;


@end
