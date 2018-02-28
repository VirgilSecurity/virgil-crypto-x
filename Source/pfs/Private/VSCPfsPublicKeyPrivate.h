//
//  VSCPfsPublicKeyPrivate.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import "VSCPfsPublicKey.h"

#import <VSCCrypto/VirgilCrypto.h>

using virgil::crypto::pfs::VirgilPFSPublicKey;

@interface VSCPfsPublicKey ()

@property (nonatomic, assign, readonly) VirgilPFSPublicKey * __nonnull cppPfsPublicKey;

@end
