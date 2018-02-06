//
//  VSCPfsResponderPrivateInfoPrivate.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import "VSCPfsResponderPrivateInfo.h"
#import <VSCCrypto/VirgilCrypto.h>

using virgil::crypto::pfs::VirgilPFSResponderPrivateInfo;

@interface VSCPfsResponderPrivateInfo ()

@property (nonatomic, assign, readonly) VirgilPFSResponderPrivateInfo * __nonnull cppPfsResponderPrivateInfo;

@end
