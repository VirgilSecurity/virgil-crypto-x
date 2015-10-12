//
//  VCCryptorTests.m
//  VirgilCypto
//
//  Created by Pavel Gorb on 9/23/15.
//  Copyright (c) 2015 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "VSSCryptor.h"
#import "VSSKeyPair.h"

@interface VC002_CryptorTests : XCTestCase

@property (nonatomic, strong) NSData* toEncrypt;

@end

@implementation VC002_CryptorTests

@synthesize toEncrypt = _toEncrypt;

- (void)setUp {
    [super setUp];
    
    NSString *message = @"Secret message which is necessary to be encrypted.";
    self.toEncrypt = [message dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
}

- (void)tearDown {
    self.toEncrypt = nil;
    [super tearDown];
}

- (void)test001_createCryptor {
    VSSCryptor *cryptor = [[VSSCryptor alloc] init];
    XCTAssertNotNil(cryptor, @"VSSCryptor instance should be created.");
}

- (void)test002_keyBasedEncryptDecrypt {
    // Encrypt:
    // Generate a new key pair
    VSSKeyPair *keyPair = [[VSSKeyPair alloc] init];
    // Generate a public key id
    NSString *publicKeyId = [[[NSUUID UUID] UUIDString] lowercaseString];
    // Create a cryptor instance
    VSSCryptor *cryptor = [[VSSCryptor alloc] init];
    // Add a key recepient to enable key-based encryption
    [cryptor addKeyRecepient:publicKeyId publicKey:keyPair.publicKey];
    // Encrypt the data
    NSData *encryptedData = [cryptor encryptData:self.toEncrypt embedContentInfo:@YES];
    XCTAssertTrue(encryptedData.length > 0, @"Cryptor should encrypt the given plain data using key-based encryption.");
    
    // Decrypt:
    // Create a completely new instance of the VCCryptor object
    VSSCryptor *decryptor = [[VSSCryptor alloc] init];
    // Decrypt data using key-based decryption
    NSData *plainData = [decryptor decryptData:encryptedData publicKeyId:publicKeyId privateKey:keyPair.privateKey keyPassword:nil];
    XCTAssertEqualObjects(plainData, self.toEncrypt, @"Initial data and decrypted data should be equal.");
}

- (void)test003_passwordBasedEncryptDecrypt {
    // Encrypt:
    NSString *password = @"secret";
    // Create a cryptor instance
    VSSCryptor *cryptor = [[VSSCryptor alloc] init];
    // Add a password recepient to enable password-based encryption
    [cryptor addPasswordRecipient:password];
    // Encrypt the data
    NSData *encryptedData = [cryptor encryptData:self.toEncrypt embedContentInfo:@YES];
    XCTAssertTrue(encryptedData.length > 0, @"Cryptor should encrypt the given plain data using password-based encryption.");
    
    // Decrypt:
    // Create a completely new instance of the VCCryptor object
    VSSCryptor *decryptor = [[VSSCryptor alloc] init];
    // Decrypt data using password-based decryption
    NSData *plainData = [decryptor decryptData:encryptedData password:password];
    XCTAssertEqualObjects(plainData, self.toEncrypt, @"Initial data and decrypted data should be equal.");
}

@end

