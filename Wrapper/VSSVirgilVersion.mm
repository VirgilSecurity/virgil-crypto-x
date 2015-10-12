//
//  VSSVirgilVersion.mm
//  VirgilCrypto
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import "VSSVirgilVersion.h"
#import <VirgilSecurity/virgil/crypto/VirgilVersion.h>

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
    
    @try {
        _frameworkVersion = new VirgilVersion();
        return self;
    }
    @catch(NSException *exc) {
        NSLog(@"Error creating VirgilVersion object: %@, %@", [exc name], [exc reason]);
        _frameworkVersion = NULL;
        return self;
    }
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
    @try {
        std::string ver = self.frameworkVersion->asString();
        version = [[NSString alloc] initWithCString:ver.c_str() encoding:NSUTF8StringEncoding];
    }
    @catch(NSException* exc) {
        NSLog(@"Error getting string version of Virgil: %@, %@", [exc name], [exc reason]);
        version = @"";
    }
    @finally {
        return version;
    }
}

- (NSNumber *)version {
    if (self.frameworkVersion == NULL) {
        return @0;
    }
    NSNumber *version = nil;
    @try {
        size_t ver = self.frameworkVersion->asNumber();
        version = [NSNumber numberWithUnsignedLongLong:ver];
    }
    @catch(NSException* exc) {
        NSLog(@"Error getting number version of Virgil: %@, %@", [exc name], [exc reason]);
        version = @0;
    }
    @finally {
        return version;
    }
}

@end
