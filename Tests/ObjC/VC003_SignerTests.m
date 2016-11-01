//
//  VCSignerTests.m
//  VirgilCypto
//
//  Created by Pavel Gorb on 9/23/15.
//  Copyright (c) 2015 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "VSCSigner.h"
#import "VSCKeyPair.h"

@interface VC003_SignerTests : XCTestCase

@property (nonatomic, strong) NSData *toSign;

@end

@implementation VC003_SignerTests

@synthesize toSign = _toSign;

- (void)setUp {
    [super setUp];
    
    NSString *message = @"Message which is need to be signed.";
    self.toSign = [message dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
}

- (void)tearDown {
    self.toSign = nil;
    [super tearDown];
}

- (void)test001_createSigner {
    VSCSigner *signer = [[VSCSigner alloc] init];
    XCTAssertNotNil(signer, @"VCSigner instance should be created.");
}

- (void)test002_composeAndVerifySignature {
    // Generate a new key pair
    VSCKeyPair *keyPair = [[VSCKeyPair alloc] init];
    
    // Compose signature:
    // Create the signer
    VSCSigner *signer = [[VSCSigner alloc] init];
    // Compose the signature
    NSData *signature = [signer signData:self.toSign privateKey:keyPair.privateKey keyPassword:nil error:nil];
    XCTAssertTrue(signature.length > 0, @"Signature should be composed.");
    
    // Verify signature:
    // Create a verifier
    VSCSigner *verifier = [[VSCSigner alloc] init];
    BOOL trusted = [verifier verifySignature:signature data:self.toSign publicKey:keyPair.publicKey error:nil];
    XCTAssertTrue(trusted, @"Signature should be correct and verified.");
}

@end
