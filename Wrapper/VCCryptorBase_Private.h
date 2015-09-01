//
//  VWCryptorBase_Private.h
//  VirgilCrypto
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import <VirgilSecurity/virgil/crypto/VirgilByteArray.h>
#import <VirgilSecurity/virgil/crypto/VirgilCipherBase.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilCipherBase;

@interface VCCryptorBase ()

@property (nonatomic, assign) VirgilCipherBase *cipher;

- (VirgilCipherBase *)createCipher;

@end