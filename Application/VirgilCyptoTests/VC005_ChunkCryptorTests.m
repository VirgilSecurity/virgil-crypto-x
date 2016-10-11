//
//  VC005_ChunkCryptorTests.m
//  VirgilCypto
//
//  Created by Pavel Gorb on 3/3/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "VSSKeyPair.h"

static const NSUInteger kPlainDataLength = 5120;
static const NSUInteger kDesiredDataChunkLength = 1024;

@interface VC005_ChunkCryptorTests : XCTestCase

@property (nonatomic, strong) NSData* toEncrypt;

- (NSData * __nonnull)randomDataWithBytes:(NSUInteger)length;

@end

@implementation VC005_ChunkCryptorTests

@synthesize toEncrypt = _toEncrypt;

- (void)setUp {
    [super setUp];
    
    self.toEncrypt = [self randomDataWithBytes:kPlainDataLength];
}

- (void)tearDown {
    self.toEncrypt = nil;
    
    [super tearDown];
}

- (void)test001_createStreamCryptor {
    VSSChunkCryptor *cryptor = [[VSSChunkCryptor alloc] init];
    XCTAssertNotNil(cryptor, @"VSSChunkCryptor instance should be created.");
}

- (void)test002_keyBasedEncryptDecrypt {
    // Encrypt:
    // Generate a new key pair
    NSError *error = nil;
    VSSKeyPair *keyPair = [[VSSKeyPair alloc] init];
    // Generate a recepient id
    NSString *recipientId = [[[NSUUID UUID] UUIDString] lowercaseString];
    // Create a cryptor instance
    VSSChunkCryptor *cryptor = [[VSSChunkCryptor alloc] init];
    // Add a key recepient to enable key-based encryption
    BOOL success = [cryptor addKeyRecipient:recipientId publicKey:keyPair.publicKey error:&error];
    if (!success || error != nil) {
        NSLog(@"Add key recipient error: %@", [error localizedDescription]);
        XCTAssertTrue(FALSE);
    }
    // Encrypt the data
    NSMutableData *encryptedData = [[NSMutableData alloc] init];
    error = nil;
    size_t actualSize = [cryptor startEncryptionWithPreferredChunkSize:kDesiredDataChunkLength error:&error];
    if (actualSize == 0 || error != nil) {
        NSLog(@"Start chunk encryption error: %@", [error localizedDescription]);
        XCTAssertTrue(FALSE);
    }
    for (NSUInteger offset = 0; offset <= [self.toEncrypt length] - 1; offset += actualSize) {
        NSData *chunk = [NSData dataWithBytesNoCopy:(char *)[self.toEncrypt bytes] + offset length:actualSize freeWhenDone:NO];
        error = nil;
        NSData *encryptedChunk = [cryptor processDataChunk:chunk error:&error];
        if (encryptedChunk.length == 0 || error != nil) {
            NSLog(@"Chunk encryption error: %@", [error localizedDescription]);
            XCTAssertTrue(FALSE);
        }
        [encryptedData appendData:encryptedChunk];
    }
    error = nil;
    success = [cryptor finishWithError:&error];
    if (!success || error != nil) {
        NSLog(@"Error finalizing cryptor: %@", [error localizedDescription]);
        XCTAssertTrue(FALSE);
    }
    XCTAssertTrue(encryptedData.length > 0, @"Encrypted data should not be empty.");
    NSData *contentInfo = [cryptor contentInfoWithError:nil];
    if (contentInfo == nil) {
        NSLog(@"There is no content info after encryption.");
        XCTAssertTrue(FALSE);
    }
    
    VSSChunkCryptor *decryptor = [[VSSChunkCryptor alloc] init];
    error = nil;
    success = [decryptor setContentInfo:contentInfo error:&error];
    if (!success || error != nil) {
        NSLog(@"Error setting content info: %@", [error localizedDescription]);
        XCTAssertTrue(FALSE);
    }
    actualSize = 0;
    actualSize = [decryptor startDecryptionWithRecipientId:recipientId privateKey:keyPair.privateKey keyPassword:nil error:&error];
    if (actualSize == 0 || error != nil) {
        NSLog(@"Start chunk decryption error: %@", [error localizedDescription]);
        XCTAssertTrue(FALSE);
    }
    
    NSMutableData *decryptedData = [[NSMutableData alloc] init];
    for (NSUInteger offset = 0; offset <= [encryptedData length] - 1; offset += actualSize) {
        NSData *chunk = [NSData dataWithBytesNoCopy:(char *)[encryptedData bytes] + offset length:actualSize freeWhenDone:NO];
        error = nil;
        NSData *decryptedChunk = [decryptor processDataChunk:chunk error:&error];
        if (decryptedChunk.length == 0 || error != nil) {
            NSLog(@"Chunk decryption error: %@", [error localizedDescription]);
            XCTAssertTrue(FALSE);
        }
        [decryptedData appendData:decryptedChunk];
    }
    error = nil;
    success = [decryptor finishWithError:&error];
    if (!success || error != nil) {
        NSLog(@"Error finalizing decryptor: %@", [error localizedDescription]);
        XCTAssertTrue(FALSE);
    }
    XCTAssertTrue(decryptedData.length > 0, @"Decrypted data should not be empty.");
    XCTAssertEqualObjects(self.toEncrypt, decryptedData, @"Initial data and decrypted data should be equal.");
}

- (void)test003_passwordBasedEncryptDecrypt {
    // Encrypt:
    NSError *error = nil;
    NSString *password = @"secret";
    // Create a cryptor instance
    VSSChunkCryptor *cryptor = [[VSSChunkCryptor alloc] init];
    // Add a key recepient to enable key-based encryption
    BOOL success = [cryptor addPasswordRecipient:password error:&error];
    if (!success || error != nil) {
        NSLog(@"Add password recipient error: %@", [error localizedDescription]);
        XCTAssertTrue(FALSE);
    }
    // Encrypt the data
    NSMutableData *encryptedData = [[NSMutableData alloc] init];
    error = nil;
    size_t actualSize = [cryptor startEncryptionWithPreferredChunkSize:kDesiredDataChunkLength error:&error];
    if (actualSize == 0 || error != nil) {
        NSLog(@"Start chunk encryption error: %@", [error localizedDescription]);
        XCTAssertTrue(FALSE);
    }
    for (NSUInteger offset = 0; offset <= [self.toEncrypt length] - 1; offset += actualSize) {
        NSData *chunk = [NSData dataWithBytesNoCopy:(char *)[self.toEncrypt bytes] + offset length:actualSize freeWhenDone:NO];
        error = nil;
        NSData *encryptedChunk = [cryptor processDataChunk:chunk error:&error];
        if (encryptedChunk.length == 0 || error != nil) {
            NSLog(@"Chunk encryption error: %@", [error localizedDescription]);
            XCTAssertTrue(FALSE);
        }
        [encryptedData appendData:encryptedChunk];
    }
    error = nil;
    success = [cryptor finishWithError:&error];
    if (!success || error != nil) {
        NSLog(@"Error finalizing cryptor: %@", [error localizedDescription]);
        XCTAssertTrue(FALSE);
    }
    XCTAssertTrue(encryptedData.length > 0, @"Encrypted data should not be empty.");
    NSData *contentInfo = [cryptor contentInfoWithError:nil];
    if (contentInfo == nil) {
        NSLog(@"There is no content info after encryption.");
        XCTAssertTrue(FALSE);
    }
    
    VSSChunkCryptor *decryptor = [[VSSChunkCryptor alloc] init];
    error = nil;
    success = [decryptor setContentInfo:contentInfo error:&error];
    if (!success || error != nil) {
        NSLog(@"Error setting content info: %@", [error localizedDescription]);
        XCTAssertTrue(FALSE);
    }
    actualSize = 0;
    actualSize = [decryptor startDecryptionWithPassword:password error:&error];
    if (actualSize == 0 || error != nil) {
        NSLog(@"Start chunk decryption error: %@", [error localizedDescription]);
        XCTAssertTrue(FALSE);
    }
    
    NSMutableData *decryptedData = [[NSMutableData alloc] init];
    for (NSUInteger offset = 0; offset <= [encryptedData length] - 1; offset += actualSize) {
        NSData *chunk = [NSData dataWithBytesNoCopy:(char *)[encryptedData bytes] + offset length:actualSize freeWhenDone:NO];
        error = nil;
        NSData *decryptedChunk = [decryptor processDataChunk:chunk error:&error];
        if (decryptedChunk.length == 0 || error != nil) {
            NSLog(@"Chunk decryption error: %@", [error localizedDescription]);
            XCTAssertTrue(FALSE);
        }
        [decryptedData appendData:decryptedChunk];
    }
    error = nil;
    success = [decryptor finishWithError:&error];
    if (!success || error != nil) {
        NSLog(@"Error finalizing decryptor: %@", [error localizedDescription]);
        XCTAssertTrue(FALSE);
    }
    XCTAssertTrue(decryptedData.length > 0, @"Decrypted data should not be empty.");
    XCTAssertEqualObjects(self.toEncrypt, decryptedData, @"Initial data and decrypted data should be equal.");
}

- (NSData *)randomDataWithBytes:(NSUInteger)length {
    NSMutableData *mutableData = [NSMutableData dataWithCapacity:length];
    for (unsigned int i = 0; i < length; i++) {
        NSInteger randomBits = arc4random();
        [mutableData appendBytes:(void *)&randomBits length:1];
    }
    return mutableData;
}


@end
