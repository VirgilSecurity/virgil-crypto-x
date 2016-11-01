//
//  VC008_TinyCryptorTests.m
//  VirgilCypto
//
//  Created by Pavel Gorb on 7/18/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import <XCTest/XCTest.h>
#import <Foundation/Foundation.h>

#import "VSCTinyCryptor.h"
#import "VSCKeyPair.h"

@interface VC008_TinyCryptorTests : XCTestCase

@property (nonatomic, strong) NSData* toEncrypt;

@end

@implementation VC008_TinyCryptorTests

@synthesize toEncrypt = _toEncrypt;

- (void)setUp {
    [super setUp];

    NSString *message = @"Secret message which have to be encrypted.";
    self.toEncrypt = [message dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
}

- (void)tearDown {
    self.toEncrypt = nil;
    [super tearDown];
}

- (void)test001_createCryptor {
    VSCTinyCryptor *cryptor = [[VSCTinyCryptor alloc] init];
    XCTAssertNotNil(cryptor, @"VSCCryptor instance should be created.");
}

- (void)test002_encryptDecrypt {
    // Encrypt:
    // Generate a new key pair
    VSCKeyPair *keyPair = [[VSCKeyPair alloc] init];
    // Create a cryptor instance
    VSCTinyCryptor *cryptor = [[VSCTinyCryptor alloc] initWithPackageSize:VSCShortSMSPackageSize];
    // encrypt data.
    NSError *error = nil;
    NSTimeInterval ti = [NSDate timeIntervalSinceReferenceDate];
    BOOL success = [cryptor encryptData:self.toEncrypt recipientPublicKey:[keyPair publicKey] error:&error];
    NSLog(@"Tiny Cryptor encryption time: %.2f", [NSDate timeIntervalSinceReferenceDate] - ti);
    if (!success || error != nil) {
        XCTFail(@"Error encrypting the data: %@", [error localizedDescription]);
    }
    
    size_t count = [cryptor packageCount];
    if (count == 0) {
        XCTFail(@"There is no encrypted data packages.");
    }
    NSMutableData *encryptedData = [[NSMutableData alloc] initWithCapacity:count * cryptor.packageSize];
    for (size_t i = 0; i < count; i++) {
        error = nil;
        NSData *package = [cryptor packageAtIndex:i error:&error];
        if (package.length == 0 || error != nil) {
            XCTFail(@"Error getting package of encrypted data from cryptor: %@", [error localizedDescription]);
            return;
        }
        
        [encryptedData appendData:package];
    }
    /// Reset cryptor after the usage.
    BOOL ok = [cryptor resetWithError:&error];
    if (!ok || error != nil) {
        XCTFail("Error resetting the cryptor: %@", [error localizedDescription]);
        return;
    }
    // Decrypt:
    // Create a completely new instance of the VCCryptor object
    VSCTinyCryptor *decryptor = [[VSCTinyCryptor alloc] initWithPackageSize:VSCShortSMSPackageSize];
    size_t len = (encryptedData.length > decryptor.packageSize) ? decryptor.packageSize : encryptedData.length;
    for (NSUInteger offset = 0; offset <= encryptedData.length - 1; offset += len) {
        
        NSData *package = [NSData dataWithBytesNoCopy:(char *)encryptedData.bytes + offset length:len freeWhenDone:NO];
        error = nil;
        ok = [decryptor addPackage:package error:&error];
        if (!ok || error != nil) {
            XCTFail(@"Error adding the package for decryption: %@", [error localizedDescription]);
            return;
        }
    }
    
    if (![decryptor packagesAccumulated]) {
        XCTFail(@"Data for decryption is corrupted or incomplete.");
        return;
    }
    
    error = nil;
    ti = [NSDate timeIntervalSinceReferenceDate];
    NSData *decryptedData = [decryptor decryptWithRecipientPrivateKey:[keyPair privateKey] recipientKeyPassword:nil error:&error];
    NSLog(@"Tiny Cryptor decryption time: %.2f", [NSDate timeIntervalSinceReferenceDate] - ti);
    if (decryptedData.length == 0 || error != nil) {
        XCTFail(@"Error decrypting the data: %@", [error localizedDescription]);
        return;
    }
    XCTAssertEqualObjects(decryptedData, self.toEncrypt, @"Initial data and decrypted data should be equal.");
}

- (void)test003_encryptSignVerifyDecrypt {
    // Encrypt+Sign:
    // Generate a new key pair for Recipient
    VSCKeyPair *keyPair_rec = [[VSCKeyPair alloc] init];
    // Generate a new key pair for Sender
    VSCKeyPair *keyPair_sen = [[VSCKeyPair alloc] init];
    // Create a cryptor instance
    VSCTinyCryptor *cryptor = [[VSCTinyCryptor alloc] initWithPackageSize:VSCShortSMSPackageSize];
    // encrypt data.
    NSError *error = nil;
    NSTimeInterval ti = [NSDate timeIntervalSinceReferenceDate];
    BOOL success = [cryptor encryptAndSignData:self.toEncrypt recipientPublicKey:[keyPair_rec publicKey] senderPrivateKey:[keyPair_sen privateKey] senderKeyPassword:nil error:&error];
    NSLog(@"Tiny Cryptor encrypt+sign time: %.2f", [NSDate timeIntervalSinceReferenceDate] - ti);
    if (!success || error != nil) {
        XCTFail(@"Error encrypting/signing the data: %@", [error localizedDescription]);
    }
    
    size_t count = [cryptor packageCount];
    if (count == 0) {
        XCTFail(@"There is no encrypted/signed data packages.");
    }
    NSMutableData *encryptedData = [[NSMutableData alloc] initWithCapacity:count * cryptor.packageSize];
    for (size_t i = 0; i < count; i++) {
        error = nil;
        NSData *package = [cryptor packageAtIndex:i error:&error];
        if (package.length == 0 || error != nil) {
            XCTFail(@"Error getting package of encrypted/signed data from cryptor: %@", [error localizedDescription]);
            return;
        }
        
        [encryptedData appendData:package];
    }
    /// Reset cryptor after the usage.
    BOOL ok = [cryptor resetWithError:&error];
    if (!ok || error != nil) {
        XCTFail("Error resetting the cryptor: %@", [error localizedDescription]);
        return;
    }
    // Verify+Decrypt:
    // Create a completely new instance of the VCCryptor object
    VSCTinyCryptor *decryptor = [[VSCTinyCryptor alloc] initWithPackageSize:VSCShortSMSPackageSize];
    size_t len = decryptor.packageSize;
    for (NSUInteger offset = 0; offset <= encryptedData.length - 1; offset += len) {
        // Recalculate len:
        len = ((double)encryptedData.length - (double)(offset + len) > 0) ? decryptor.packageSize : encryptedData.length - offset;
        NSData *package = [NSData dataWithBytesNoCopy:(char *)encryptedData.bytes + offset length:len freeWhenDone:NO];
        error = nil;
        ok = [decryptor addPackage:package error:&error];
        if (!ok || error != nil) {
            XCTFail(@"Error adding the package for verification/decryption: %@", [error localizedDescription]);
            return;
        }
    }
    
    if (![decryptor packagesAccumulated]) {
        XCTFail(@"Data for verification/decryption is corrupted or incomplete.");
        return;
    }
    
    error = nil;
    ti = [NSDate timeIntervalSinceReferenceDate];
    NSData *decryptedData = [decryptor verifyAndDecryptWithSenderPublicKey:[keyPair_sen publicKey] recipientPrivateKey:[keyPair_rec privateKey] recipientKeyPassword:nil error:&error];
    NSLog(@"Tiny Cryptor verification/decryption time: %.2f", [NSDate timeIntervalSinceReferenceDate] - ti);
    if (decryptedData.length == 0 || error != nil) {
        XCTFail(@"Error verification/decrypting the data: %@", [error localizedDescription]);
        return;
    }
    XCTAssertEqualObjects(decryptedData, self.toEncrypt, @"Initial data and decrypted data should be equal.");
}


@end
