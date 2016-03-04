//
//  VC006_StreamSignerTests.m
//  VirgilCypto
//
//  Created by Pavel Gorb on 3/3/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "VSSStreamSigner.h"
#import "VSSKeyPair.h"

@interface VC006_StreamSignerTests : XCTestCase

@property (nonatomic, strong) NSData *toSign;

@end

@implementation VC006_StreamSignerTests

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
    VSSStreamSigner *signer = [[VSSStreamSigner alloc] init];
    XCTAssertNotNil(signer, @"VSSStreamSigner instance should be created.");
}

- (void)test002_composeAndVerifySignature {
    // Generate a new key pair
    VSSKeyPair *keyPair = [[VSSKeyPair alloc] init];
    
    NSError *error = nil;
    // Compose signature:
    // Create the signer
    VSSStreamSigner *signer = [[VSSStreamSigner alloc] init];
    // Compose the signature
    NSInputStream *is = [NSInputStream inputStreamWithData:self.toSign];
    NSData *signature = [signer signStreamData:is privateKey:keyPair.privateKey keyPassword:nil error:&error];
    if (error != nil) {
        NSLog(@"Error composing the signature: %@", [error localizedDescription]);
    }
    XCTAssertTrue(signature.length > 0, @"Signature should be composed.");
    
    // Verify signature:
    // Create a verifier
    VSSStreamSigner *verifier = [[VSSStreamSigner alloc] init];
    NSInputStream *isv = [NSInputStream inputStreamWithData:self.toSign];
    error = nil;
    BOOL trusted = [verifier verifySignature:signature fromStream:isv publicKey:keyPair.publicKey error:&error];
    if (error != nil) {
        NSLog(@"Error composing the signature: %@", [error localizedDescription]);
    }
    XCTAssertTrue(trusted, @"Signature should be correct and verified.");
}

@end
