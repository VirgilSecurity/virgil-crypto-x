//
//  VC004_StreamCryptorTests.m
//  VirgilCypto
//
//  Created by Pavel Gorb on 3/1/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "VSCStreamCryptor.h"
#import "VSCKeyPair.h"

@interface VC004_StreamCryptorTests : XCTestCase

@property (nonatomic, strong) NSData* toEncrypt;

@end

@implementation VC004_StreamCryptorTests

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

- (void)test001_createStreamCryptor {
    VSCStreamCryptor *cryptor = [[VSCStreamCryptor alloc] init];
    XCTAssertNotNil(cryptor, @"VSCStreamCryptor instance should be created.");
}

- (void)test002_keyBasedEncryptDecrypt {
    // Encrypt:
    // Generate a new key pair
    NSError *error = nil;
    VSCKeyPair *keyPair = [[VSCKeyPair alloc] init];
    // Generate a recepient id
    NSString *recipientId = [[[NSUUID UUID] UUIDString] lowercaseString];
    // Create a cryptor instance
    VSCStreamCryptor *cryptor = [[VSCStreamCryptor alloc] init];
    // Add a key recepient to enable key-based encryption
    BOOL success = [cryptor addKeyRecipient:recipientId publicKey:keyPair.publicKey error:&error];
    if (!success || error != nil) {
        NSLog(@"Add key recipient error: %@", [error localizedDescription]);
        XCTAssertTrue(FALSE);
    }
    // Encrypt the data
    NSInputStream *istream = [NSInputStream inputStreamWithData:self.toEncrypt];
    NSOutputStream *ostream = [NSOutputStream outputStreamToMemory];
    
    NSTimeInterval ti = [NSDate timeIntervalSinceReferenceDate];
    success = [cryptor encryptDataFromStream:istream toStream:ostream embedContentInfo:YES error:&error];
    NSLog(@"Encryption key-based time: %.2f", [NSDate timeIntervalSinceReferenceDate] - ti);
    if (!success || error != nil) {
        NSLog(@"Encryption error: %@", [error localizedDescription]);
        XCTAssertTrue(FALSE);
    }
    NSData *encryptedData = (NSData *)[ostream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
    XCTAssertTrue(encryptedData.length > 0, @"Cryptor should encrypt the given input stream data using key-based encryption.");
    
    // Decrypt:
    // Create a completely new instance of the VCCryptor object
    VSCStreamCryptor *decryptor = [[VSCStreamCryptor alloc] init];
    NSInputStream *idecstream = [NSInputStream inputStreamWithData:encryptedData];
    NSOutputStream *odecsctream = [NSOutputStream outputStreamToMemory];
    
    // Decrypt data using key-based decryption
    error = nil;
    ti = [NSDate timeIntervalSinceReferenceDate];
    success = [decryptor decryptFromStream:idecstream toStream:odecsctream recipientId:recipientId privateKey:keyPair.privateKey keyPassword:nil error:&error];
    NSLog(@"Decryption key-based time: %.2f", [NSDate timeIntervalSinceReferenceDate] - ti);;
    if (!success || error != nil) {
        NSLog(@"Decryption error: %@", [error localizedDescription]);
        XCTAssertTrue(FALSE);
    }
    NSData *plainData = (NSData *)[odecsctream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
    XCTAssertEqualObjects(plainData, self.toEncrypt, @"Initial data and decrypted data should be equal.");
}

- (void)test003_passwordBasedEncryptDecrypt {
    // Encrypt:
    NSError *error = nil;
    NSString *password = @"secret";
    // Create a cryptor instance
    VSCStreamCryptor *cryptor = [[VSCStreamCryptor alloc] init];
    // Add a password recepient to enable password-based encryption
    BOOL success = [cryptor addPasswordRecipient:password error:&error];
    if (!success || error != nil) {
        NSLog(@"Add password recipient error: %@", [error localizedDescription]);
        XCTAssertTrue(FALSE);
    }
    
    NSInputStream *istream = [NSInputStream inputStreamWithData:self.toEncrypt];
    NSOutputStream *ostream = [NSOutputStream outputStreamToMemory];
    // Encrypt the data
    NSTimeInterval ti = [NSDate timeIntervalSinceReferenceDate];
    success = [cryptor encryptDataFromStream:istream toStream:ostream embedContentInfo:NO error:&error];
    NSLog(@"Encryption password-based time: %.2f", [NSDate timeIntervalSinceReferenceDate] - ti);
    if (!success || error != nil) {
        NSLog(@"Encryption error: %@", [error localizedDescription]);
        XCTAssertTrue(FALSE);
    }
    NSData *encryptedData = (NSData *)[ostream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
    NSData *contentInfo = [cryptor contentInfoWithError:nil];
    if (contentInfo == nil) {
        NSLog(@"There is no content info after encryption.");
        XCTAssertTrue(FALSE);
    }
    XCTAssertTrue(encryptedData.length > 0, @"Cryptor should encrypt the given plain data using password-based encryption.");
    
    // Decrypt:
    // Create a completely new instance of the VCCryptor object
    VSCStreamCryptor *decryptor = [[VSCStreamCryptor alloc] init];
    error = nil;
    success = [decryptor setContentInfo:contentInfo error:&error];
    if (!success || error != nil) {
        NSLog(@"Error setting content info: %@", [error localizedDescription]);
        XCTAssertTrue(FALSE);
    }
    NSInputStream *idecstream = [NSInputStream inputStreamWithData:encryptedData];
    NSOutputStream *odecsctream = [NSOutputStream outputStreamToMemory];
    error = nil;
    // Decrypt data using password-based decryption
    ti = [NSDate timeIntervalSinceReferenceDate];
    success = [decryptor decryptFromStream:idecstream toStream:odecsctream password:password error:&error];
    NSLog(@"Decryption password-based time: %.2f", [NSDate timeIntervalSinceReferenceDate] - ti);
    if (!success || error != nil) {
        NSLog(@"Decryption error: %@", [error localizedDescription]);
        XCTAssertTrue(FALSE);
    }
    NSData *plainData = (NSData *)[odecsctream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
    XCTAssertEqualObjects(plainData, self.toEncrypt, @"Initial data and decrypted data should be equal.");
}

@end
