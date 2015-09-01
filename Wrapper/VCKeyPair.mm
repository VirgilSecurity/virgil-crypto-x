//
//  VCKeyPair.mm
//  VirgilCrypto
//
//  Created by Pavel Gorb on 2/3/15.
//  Copyright (c) 2015 VirgilSecurity, Inc. All rights reserved.
//

#import "VCKeyPair.h"
#import <VirgilSecurity/virgil/crypto/VirgilByteArray.h>
#import <VirgilSecurity/virgil/crypto/VirgilKeyPair.h>

using virgil::crypto::VirgilByteArray;
using namespace virgil::crypto;

@interface VCKeyPair ()

@property (nonatomic, assign) VirgilKeyPair* keyPair;

@end

@implementation VCKeyPair

@synthesize keyPair = _keyPair;

#pragma mark - Lifecycle

- (instancetype)init {
    return [self initWithPassword:nil];
}

- (instancetype)initWithPassword:(NSString *)password {
    self = [super init];
    if( nil == self ) {
        return nil;
    }

    @try {
        if( 0 >= [password length] ) {
            _keyPair = new VirgilKeyPair();
        } else {
            std::string pwd = std::string([password UTF8String]);
            _keyPair = new VirgilKeyPair(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pwd.data(), pwd.size()));
        }
        
        return self;
    }
    @catch(NSException* exc) {
        NSLog(@"Error creating VirgilKeyPair object: %@, %@", [exc name], [exc reason]);
        return nil;
    }
}

- (void)dealloc {
    if (_keyPair != NULL) {
        delete _keyPair;
        _keyPair = NULL;
    }
}

#pragma mark - Public class logic

- (NSData *)publicKey {
    if( self.keyPair == NULL ) {
        return nil;
    }
    NSData *publicKey = nil;
    @try {
        VirgilByteArray pkey = self.keyPair->publicKey();
        publicKey = [NSData dataWithBytes:pkey.data() length:pkey.size()];
    }
    @catch(NSException* exc) {
        NSLog(@"Error getting Public Key object: %@, %@", [exc name], [exc reason]);
        publicKey = nil;
    }
    @finally {
        return publicKey;
    }
}


- (NSData *)privateKey {
    if( self.keyPair == NULL ) {
        return nil;
    }
    
    NSData *privateKey = nil;
    @try {
        VirgilByteArray pkey = self.keyPair->privateKey();
        privateKey = [NSData dataWithBytes:pkey.data() length:pkey.size()];
    }
    @catch(NSException* exc) {
        NSLog(@"Error getting Private Key object: %@, %@", [exc name], [exc reason]);
        privateKey = nil;
    }
    @finally {
        return privateKey;
    }
}

@end
