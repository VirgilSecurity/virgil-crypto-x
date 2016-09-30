//
//  VC006_StreamSignerTests.m
//  VirgilCypto
//
//  Created by Pavel Gorb on 3/3/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "VSCStreamSigner.h"
#import "VSCKeyPair.h"

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
    VSCStreamSigner *signer = [[VSCStreamSigner alloc] init];
    XCTAssertNotNil(signer, @"VSCStreamSigner instance should be created.");
}

- (void)test002_composeAndVerifySignature {
    // Generate a new key pair
    VSCKeyPair *keyPair = [[VSCKeyPair alloc] init];
    
    NSError *error = nil;
    // Compose signature:
    // Create the signer
    VSCStreamSigner *signer = [[VSCStreamSigner alloc] init];
    // Compose the signature
    NSInputStream *is = [NSInputStream inputStreamWithData:self.toSign];
    NSData *signature = [signer signStreamData:is privateKey:keyPair.privateKey keyPassword:nil error:&error];
    if (error != nil) {
        NSLog(@"Error composing the signature: %@", [error localizedDescription]);
    }
    XCTAssertTrue(signature.length > 0, @"Signature should be composed.");
    
    // Verify signature:
    // Create a verifier
    VSCStreamSigner *verifier = [[VSCStreamSigner alloc] init];
    NSInputStream *isv = [NSInputStream inputStreamWithData:self.toSign];
    error = nil;
    BOOL trusted = [verifier verifySignature:signature fromStream:isv publicKey:keyPair.publicKey error:&error];
    if (error != nil) {
        NSLog(@"Error composing the signature: %@", [error localizedDescription]);
    }
    XCTAssertTrue(trusted, @"Signature should be correct and verified.");
}

@end
