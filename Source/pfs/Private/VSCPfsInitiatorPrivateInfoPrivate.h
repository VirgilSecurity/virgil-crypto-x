//
//  VSCPfsInitiatorPrivateInfoPrivate.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import "VSCPfsInitiatorPrivateInfo.h"

#import <virgil/crypto/pfs/VirgilPFSInitiatorPrivateInfo.h>

using virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo;

@interface VSCPfsInitiatorPrivateInfo ()

@property (nonatomic, assign, readonly) VirgilPFSInitiatorPrivateInfo * __nonnull cppPfsInitiatorPrivateInfo;

@end
