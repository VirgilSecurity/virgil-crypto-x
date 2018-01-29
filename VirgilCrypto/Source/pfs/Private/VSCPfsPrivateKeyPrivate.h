//
//  VSCPfsPrivateKeyPrivate.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import "VSCPfsPrivateKey.h"

#import <virgil/crypto/pfs/VirgilPFSPrivateKey.h>

using virgil::crypto::pfs::VirgilPFSPrivateKey;

@interface VSCPfsPrivateKey ()

@property (nonatomic, assign, readonly) VirgilPFSPrivateKey * __nonnull cppPfsPrivateKey;

@end
