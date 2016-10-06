//
//  VSCHashTests.m
//  VirgilCypto
//
//  Created by Yaroslav Tytarenko on 10/5/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "VSCHash.h"
#import "VSCByteArrayUtils.h"

@interface VSCHashTests : XCTestCase

@end

@implementation VSCHashTests


- (void)testCalculateMD5 {
    VSCHash *h = [[VSCHash alloc] initWithAlgorithm:VSCAlgorithmMD5];
    NSString *plainString = @"secret";
    NSString *expectedHashString = @"5ebe2294ecd0e0f08eab7690d2a6ee69";

    XCTAssertNil([h hash:[NSData data]]);
    XCTAssertNil([h hash:nil]);
    
    NSData *hashData = [h hash:[plainString dataUsingEncoding:NSUTF8StringEncoding]];
    NSString *hexString = [VSCByteArrayUtils hexStringFromData:hashData];

    XCTAssertEqualObjects(expectedHashString, hexString);
}

- (void)testCalculateSHA1 {
    VSCHash *h = [[VSCHash alloc] initWithAlgorithm:VSCAlgorithmSHA1];
    NSString *plainString = @"secret";
    NSString *expectedHashString = @"e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4";
    
    XCTAssertNil([h hash:[NSData data]]);
    XCTAssertNil([h hash:nil]);
    
    NSData *hashData = [h hash:[plainString dataUsingEncoding:NSUTF8StringEncoding]];
    NSString *hexString = [VSCByteArrayUtils hexStringFromData:hashData];
    
    XCTAssertEqualObjects(expectedHashString, hexString);
}

- (void)testCalculateSHA224 {
    VSCHash *h = [[VSCHash alloc] initWithAlgorithm:VSCAlgorithmSHA224];
    NSString *plainString = @"secret";
    NSString *expectedHashString = @"95c7fbca92ac5083afda62a564a3d014fc3b72c9140e3cb99ea6bf12";
    
    XCTAssertNil([h hash:[NSData data]]);
    XCTAssertNil([h hash:nil]);
    
    NSData *hashData = [h hash:[plainString dataUsingEncoding:NSUTF8StringEncoding]];
    NSString *hexString = [VSCByteArrayUtils hexStringFromData:hashData];
    
    XCTAssertEqualObjects(expectedHashString, hexString);
}

- (void)testCalculateSHA256 {
    VSCHash *h = [[VSCHash alloc] initWithAlgorithm:VSCAlgorithmSHA256];
    NSString *plainString = @"abc";
    NSString *expectedHashString = @"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    
    XCTAssertNil([h hash:[NSData data]]);
    XCTAssertNil([h hash:nil]);
    
    NSData *hashData = [h hash:[plainString dataUsingEncoding:NSUTF8StringEncoding]];
    NSString *hexString = [VSCByteArrayUtils hexStringFromData:hashData];
    
    XCTAssertEqualObjects(expectedHashString, hexString);
}

- (void)testCalculateSHA384 {
    VSCHash *h = [[VSCHash alloc] initWithAlgorithm:VSCAlgorithmSHA384];
    NSString *plainString = @"secret";
    NSString *expectedHashString = @"58a775ba4112be3005ae4407ce757d88fda71d40497bb8026ecac54d4e3ffc7232ce8de3ab5acb30ae39760fee7c53ed";
    
    XCTAssertNil([h hash:[NSData data]]);
    XCTAssertNil([h hash:nil]);
    
    NSData *hashData = [h hash:[plainString dataUsingEncoding:NSUTF8StringEncoding]];
    NSString *hexString = [VSCByteArrayUtils hexStringFromData:hashData];
    
    XCTAssertEqualObjects(expectedHashString, hexString);
}

- (void)testCalculateSHA512 {
    VSCHash *h = [[VSCHash alloc] initWithAlgorithm:VSCAlgorithmSHA512];
    NSString *plainString = @"secret";
    NSString *expectedHashString = @"bd2b1aaf7ef4f09be9f52ce2d8d599674d81aa9d6a4421696dc4d93dd0619d682ce56b4d64a9ef097761ced99e0f67265b5f76085e5b0ee7ca4696b2ad6fe2b2";
    
    XCTAssertNil([h hash:[NSData data]]);
    XCTAssertNil([h hash:nil]);
    
    NSData *hashData = [h hash:[plainString dataUsingEncoding:NSUTF8StringEncoding]];
    NSString *hexString = [VSCByteArrayUtils hexStringFromData:hashData];
    
    XCTAssertEqualObjects(expectedHashString, hexString);
}

@end
