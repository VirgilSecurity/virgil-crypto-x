//
//  VSCVirgilVersion.mm
//  VirgilFoundation
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import "VSCVirgilVersion.h"
#import <VSCCrypto/VirgilCrypto.h>

using virgil::crypto::VirgilVersion;

@implementation VSCVirgilVersion

+ (NSUInteger)asNumber {
    NSUInteger version = 0;
    try {
        version = VirgilVersion::asNumber();
    }
    catch(...) {
        version = 0;
    }
    
    return version;
}

+ (NSString *)asString {
    NSString *version = nil;
    try {
        std::string ver = VirgilVersion::asString();
        version = [[NSString alloc] initWithCString:ver.c_str() encoding:NSUTF8StringEncoding];
    }
    catch(...) {
        version = @"";
    }
    
    return version;
}

+ (NSUInteger)majorVersion {
    NSUInteger version = 0;
    try {
        version = VirgilVersion::majorVersion();
    }
    catch(...) {
        version = 0;
    }
    
    return version;
}

+ (NSUInteger)minorVersion {
    NSUInteger version = 0;
    try {
        version = VirgilVersion::minorVersion();
    }
    catch(...) {
        version = 0;
    }
    
    return version;
}

+ (NSUInteger)patchVersion {
    NSUInteger version = 0;
    try {
        version = VirgilVersion::patchVersion();
    }
    catch(...) {
        version = 0;
    }
    
    return version;
}

+ (NSString *)fullName {
    NSString *fullName = nil;
    try {
        std::string ver = VirgilVersion::fullName();
        fullName = [[NSString alloc] initWithCString:ver.c_str() encoding:NSUTF8StringEncoding];
    }
    catch(...) {
        fullName = @"";
    }
    
    return fullName;
}

@end
