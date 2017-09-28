//
//  VC010_HashTests.m
//  VirgilCypto
//
//  Created by Yaroslav Tytarenko on 10/5/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "VSCHash.h"
#import "VSCByteArrayUtils.h"

@interface VC010_HashTests : XCTestCase

@end

@implementation VC010_HashTests


- (void)test001_calculateMD5 {
    VSCHash *h = [[VSCHash alloc] initWithAlgorithm:VSCHashAlgorithmMD5];
    NSString *plainString = @"secret";
    NSString *expectedHashString = @"5ebe2294ecd0e0f08eab7690d2a6ee69";

    XCTAssert([[[h hash:[[NSData alloc] init]] base64EncodedStringWithOptions:0] isEqualToString:@"1B2M2Y8AsgTpgAmY7PhCfg=="]);
    XCTAssert([[[h hash:nil] base64EncodedStringWithOptions:0] isEqualToString:@"1B2M2Y8AsgTpgAmY7PhCfg=="]);
    
    NSData *hashData = [h hash:[plainString dataUsingEncoding:NSUTF8StringEncoding]];
    NSString *hexString = [VSCByteArrayUtils hexStringFromData:hashData];

    XCTAssertEqualObjects(expectedHashString, hexString);
}

- (void)test002_calculateSHA1 {
    VSCHash *h = [[VSCHash alloc] initWithAlgorithm:VSCHashAlgorithmSHA1];
    NSString *plainString = @"secret";
    NSString *expectedHashString = @"e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4";
    
    XCTAssert([[[h hash:[[NSData alloc] init]] base64EncodedStringWithOptions:0] isEqualToString:@"2jmj7l5rSw0yVb/vlWAYkK/YBwk="]);
    XCTAssert([[[h hash:nil] base64EncodedStringWithOptions:0] isEqualToString:@"2jmj7l5rSw0yVb/vlWAYkK/YBwk="]);
    
    NSData *hashData = [h hash:[plainString dataUsingEncoding:NSUTF8StringEncoding]];
    NSString *hexString = [VSCByteArrayUtils hexStringFromData:hashData];
    
    XCTAssertEqualObjects(expectedHashString, hexString);
}

- (void)test003_calculateSHA224 {
    VSCHash *h = [[VSCHash alloc] initWithAlgorithm:VSCHashAlgorithmSHA224];
    NSString *plainString = @"secret";
    NSString *expectedHashString = @"95c7fbca92ac5083afda62a564a3d014fc3b72c9140e3cb99ea6bf12";
    
    XCTAssert([[[h hash:[[NSData alloc] init]] base64EncodedStringWithOptions:0] isEqualToString:@"0UoCjCo6K8lHYQK7KII0xBWisB+CjqYqxbPkLw=="]);
    XCTAssert([[[h hash:nil] base64EncodedStringWithOptions:0] isEqualToString:@"0UoCjCo6K8lHYQK7KII0xBWisB+CjqYqxbPkLw=="]);
    
    NSData *hashData = [h hash:[plainString dataUsingEncoding:NSUTF8StringEncoding]];
    NSString *hexString = [VSCByteArrayUtils hexStringFromData:hashData];
    
    XCTAssertEqualObjects(expectedHashString, hexString);
}

- (void)test004_calculateSHA256 {
    VSCHash *h = [[VSCHash alloc] initWithAlgorithm:VSCHashAlgorithmSHA256];
    NSString *plainString = @"abc";
    NSString *expectedHashString = @"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    
    XCTAssert([[[h hash:[[NSData alloc] init]] base64EncodedStringWithOptions:0] isEqualToString:@"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="]);
    XCTAssert([[[h hash:nil] base64EncodedStringWithOptions:0] isEqualToString:@"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="]);
    
    NSData *hashData = [h hash:[plainString dataUsingEncoding:NSUTF8StringEncoding]];
    NSString *hexString = [VSCByteArrayUtils hexStringFromData:hashData];
    
    XCTAssertEqualObjects(expectedHashString, hexString);
}

- (void)test005_calculateSHA384 {
    VSCHash *h = [[VSCHash alloc] initWithAlgorithm:VSCHashAlgorithmSHA384];
    NSString *plainString = @"secret";
    NSString *expectedHashString = @"58a775ba4112be3005ae4407ce757d88fda71d40497bb8026ecac54d4e3ffc7232ce8de3ab5acb30ae39760fee7c53ed";
    
    XCTAssert([[[h hash:[[NSData alloc] init]] base64EncodedStringWithOptions:0] isEqualToString:@"OLBgp1GsljhM2TJ+sbHjaiH9txEUvgdDTAzHv2P24donTt6/529l+9Ua0vFImLlb"]);
    XCTAssert([[[h hash:nil] base64EncodedStringWithOptions:0] isEqualToString:@"OLBgp1GsljhM2TJ+sbHjaiH9txEUvgdDTAzHv2P24donTt6/529l+9Ua0vFImLlb"]);
    
    NSData *hashData = [h hash:[plainString dataUsingEncoding:NSUTF8StringEncoding]];
    NSString *hexString = [VSCByteArrayUtils hexStringFromData:hashData];
    
    XCTAssertEqualObjects(expectedHashString, hexString);
}

- (void)test005_calculateSHA512 {
    VSCHash *h = [[VSCHash alloc] initWithAlgorithm:VSCHashAlgorithmSHA512];
    NSString *plainString = @"secret";
    NSString *expectedHashString = @"bd2b1aaf7ef4f09be9f52ce2d8d599674d81aa9d6a4421696dc4d93dd0619d682ce56b4d64a9ef097761ced99e0f67265b5f76085e5b0ee7ca4696b2ad6fe2b2";
    
    XCTAssert([[[h hash:[[NSData alloc] init]] base64EncodedStringWithOptions:0] isEqualToString:@"z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="]);
    XCTAssert([[[h hash:nil] base64EncodedStringWithOptions:0] isEqualToString:@"z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="]);
    
    NSData *hashData = [h hash:[plainString dataUsingEncoding:NSUTF8StringEncoding]];
    NSString *hexString = [VSCByteArrayUtils hexStringFromData:hashData];
    
    XCTAssertEqualObjects(expectedHashString, hexString);
}

- (void)test006_calculateSHA256_Chunks {
    VSCHash *h = [[VSCHash alloc] initWithAlgorithm:VSCHashAlgorithmSHA256];
    NSString *plainString = @"abc";
    NSString *expectedHashString = @"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    
    XCTAssert([[[h hash:[[NSData alloc] init]] base64EncodedStringWithOptions:0] isEqualToString:@"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="]);
    XCTAssert([[[h hash:nil] base64EncodedStringWithOptions:0] isEqualToString:@"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="]);
    
    NSData *data = [plainString dataUsingEncoding:NSUTF8StringEncoding];
    
    [h start];
    [h updateWithData:[data subdataWithRange:NSMakeRange(0, 1)]];
    [h updateWithData:[data subdataWithRange:NSMakeRange(1, 1)]];
    [h updateWithData:[data subdataWithRange:NSMakeRange(2, 1)]];
    NSData *hashData = [h finish];
    NSString *hexString = [VSCByteArrayUtils hexStringFromData:hashData];
    
    XCTAssertEqualObjects(expectedHashString, hexString);
}

@end
