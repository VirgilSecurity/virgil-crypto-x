//
//  VCKeyPairTests.m
//  VirgilCypto
//
//  Created by Pavel Gorb on 9/23/15.
//  Copyright (c) 2015 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "VSCKeyPair.h"

@interface VC001_KeyPairTests : XCTestCase

@end

@implementation VC001_KeyPairTests

- (void)test001_createKeyPair {
    VSCKeyPair *keyPair = [VSCKeyPair new];
    XCTAssertNotNil(keyPair, @"VSCKeyPair instance should be created.");
    XCTAssertTrue(keyPair.publicKey.length > 0, @"Public key should be generated for the new key pair.");
    XCTAssertTrue(keyPair.privateKey.length > 0, @"Private key should be generated for the new key pair.");
    
    NSString *privateKeyString = [[NSString alloc] initWithData:keyPair.privateKey encoding:NSUTF8StringEncoding];
    NSRange range = [privateKeyString rangeOfString:@"ENCRYPTED" options:NSLiteralSearch | NSCaseInsensitiveSearch];
    XCTAssertTrue(range.length == 0, @"Private key should be generated in plain form.");
}

- (void)test002_createKeyPairWithPassword {
//    NSString *password = @"secret";
//    VSCKeyPair *keyPair = [[VSCKeyPair alloc] initWithPassword:password];
//    XCTAssertNotNil(keyPair, @"VSCKeyPair instance should be created.");
//    XCTAssertTrue(keyPair.publicKey.length > 0, @"Public key should be generated for the new key pair.");
//    XCTAssertTrue(keyPair.privateKey.length > 0, @"Private key should be generated for the new key pair.");
//    
//    NSString *privateKeyString = [[NSString alloc] initWithData:keyPair.privateKey encoding:NSUTF8StringEncoding];
//    NSRange range = [privateKeyString rangeOfString:@"ENCRYPTED" options:NSLiteralSearch | NSCaseInsensitiveSearch];
//    XCTAssertTrue(range.length != 0, @"Private key should be generated protected by the password provided to initializer.");
}

- (void)test003_encryptDecryptPrivateKey {
    VSCKeyPair *keyPair = [VSCKeyPair new];
    NSString *password = @"secret";

    NSData* encryptedPrivateKey = [VSCKeyPair encryptPrivateKey:keyPair.privateKey privateKeyPassword:password];
    XCTAssertNotNil(encryptedPrivateKey, @"Encrypted private key should be created");
    XCTAssertTrue(encryptedPrivateKey.length > 0, @"Encrypted private key should be generated for the new data");

    NSData* decryptedPrivateKey = [VSCKeyPair decryptPrivateKey:encryptedPrivateKey privateKeyPassword:password];
    XCTAssertNotNil(decryptedPrivateKey, @"Encrypted private key should be created");
    XCTAssertTrue(decryptedPrivateKey.length > 0, @"Encrypted private key should be generated for the new data");
    XCTAssertEqualObjects(decryptedPrivateKey, keyPair.privateKey, @"");
}

- (void)test004_extractPublicKeysToPemAndDerFormats {
    VSCKeyPair *keyPair = [VSCKeyPair new];

    NSData *pemData = [VSCKeyPair publicKeyToPEM:keyPair.publicKey];
    NSString *pem = [[NSString alloc] initWithData:pemData encoding:NSUTF8StringEncoding];
    NSRange isRange = [pem rangeOfString:@"BEGIN PUBLIC KEY" options:NSCaseInsensitiveSearch];
    XCTAssertTrue(pemData.length > 0, @"PEM data should not be empty");
    XCTAssertTrue(isRange.location != NSNotFound, @"PEM string should contains 'BEGIN PUBLIC KEY' symbols");

    NSData *derData = [VSCKeyPair publicKeyToDER:keyPair.publicKey];
    XCTAssertTrue(derData.length > 0, @"DER data should not be empty");
}

- (void)test005_extractPrivateKeysToPemAndDerFormats {
    VSCKeyPair *keyPair = [VSCKeyPair new];

    NSData *pemData = [VSCKeyPair privateKeyToPEM:keyPair.privateKey];
    NSString *pem = [[NSString alloc] initWithData:pemData encoding:NSUTF8StringEncoding];
    NSRange isRange = [pem rangeOfString:@"BEGIN PRIVATE KEY" options:NSCaseInsensitiveSearch];
    XCTAssertTrue(pemData.length > 0, @"PEM data should not be empty");
    XCTAssertTrue(isRange.location != NSNotFound, @"PEM string should contains 'BEGIN PRIVATE KEY' symbols");

    NSData *derData = [VSCKeyPair privateKeyToDER:keyPair.privateKey];
    XCTAssertTrue(derData.length > 0, @"DER data should not be empty");
}

- (void)test006_extractPrivateKeysWithPasswordToPemAndDerFormats {
    VSCKeyPair *keyPair = [VSCKeyPair new];
    NSString *password = @"secret";

    NSData *pemData = [VSCKeyPair privateKeyToPEM:keyPair.privateKey privateKeyPassword:password];
    NSString *pem = [[NSString alloc] initWithData:pemData encoding:NSUTF8StringEncoding];
    NSRange isRange = [pem rangeOfString:@"BEGIN ENCRYPTED PRIVATE KEY" options:NSCaseInsensitiveSearch];
    XCTAssertTrue(pemData.length > 0, @"PEM data should not be empty");
    XCTAssertTrue(isRange.location != NSNotFound, @"PEM string should contains 'BEGIN ENCRYPTED PRIVATE KEY' symbols");

    NSData *derData = [VSCKeyPair privateKeyToDER:keyPair.privateKey privateKeyPassword:password];
    XCTAssertTrue(derData.length > 0, @"DER data should not be empty");
}

@end
