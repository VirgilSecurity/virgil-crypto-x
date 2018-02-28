//
//  VSCPfsResponderPublicInfoPrivate.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import "VSCPfsResponderPublicInfo.h"

#import <VSCCrypto/VirgilCrypto.h>

using virgil::crypto::pfs::VirgilPFSResponderPublicInfo;

@interface VSCPfsResponderPublicInfo ()

@property (nonatomic, assign, readonly) VirgilPFSResponderPublicInfo * __nonnull cppPfsResponderPublicInfo;

@end
