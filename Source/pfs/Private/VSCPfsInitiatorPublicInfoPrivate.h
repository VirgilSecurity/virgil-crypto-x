//
//  VSCPfsInitiatorPublicInfoPrivate.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import "VSCPfsInitiatorPublicInfo.h"

#import <virgil/crypto/pfs/VirgilPFSInitiatorPublicInfo.h>

using virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo;

@interface VSCPfsInitiatorPublicInfo ()

@property (nonatomic, assign, readonly) VirgilPFSInitiatorPublicInfo * __nonnull cppPfsInitiatorPublicInfo;

@end
