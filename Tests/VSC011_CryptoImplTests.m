//
//  VSC011_CryptoImplTests.m
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/19/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

@import VirgilCrypto;
@import VirgilCryptoAPI;

@interface VSC011_CryptoImplTests : XCTestCase

@end

@implementation VSC011_CryptoImplTests

- (void)test {
    VSCVirgilCrypto *crypto = [[VSCVirgilCrypto alloc] init];
    
    
    
    VSCKeyPair *keyPair = [[VSCKeyPair alloc] init];
    
    VSCVirgilPrivateKey *privateKey = [[VSCVirgilPrivateKey alloc] initWithKey:keyPair.privateKey password:nil];
    
    
}

@end
