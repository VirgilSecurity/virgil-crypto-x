//
//  VSSVirgilVersion.mm
//  VirgilFoundation
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import "VSSVirgilVersion.h"
#import <VirgilCrypto/virgil/crypto/VirgilVersion.h>

using virgil::crypto::VirgilVersion;

@interface VSSVirgilVersion ()

@property(nonatomic, assign) VirgilVersion *frameworkVersion;

@end

@implementation VSSVirgilVersion

@synthesize frameworkVersion = _frameworkVersion;

#pragma mark - Lifecycle

- (instancetype)init {
    self = [super init];
    if (self == nil) {
        return nil;
    }
    
    _frameworkVersion = new VirgilVersion();
    return self;
}

- (void)dealloc {
    if (_frameworkVersion != NULL) {
        delete _frameworkVersion;
        _frameworkVersion = NULL;
    }
}

#pragma mark - Class logic

- (NSString *)versionString {
    if (self.frameworkVersion == NULL) {
        return @"";
    }
    NSString *version = nil;
    std::string ver = self.frameworkVersion->asString();
    version = [[NSString alloc] initWithCString:ver.c_str() encoding:NSUTF8StringEncoding];
    return version;
}

- (NSNumber *)version {
    if (self.frameworkVersion == NULL) {
        return @0;
    }
    NSNumber *version = nil;
    size_t ver = self.frameworkVersion->asNumber();
    version = [NSNumber numberWithUnsignedLongLong:ver];
    return version;
}

@end
