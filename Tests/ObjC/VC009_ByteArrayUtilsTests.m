//
//  VC009_ByteArrayUtilsTests.m
//  VirgilCypto
//
//  Created by Yaroslav Tytarenko on 10/4/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "VSCByteArrayUtils.h"


@interface VC009_ByteArrayUtilsTests : XCTestCase

@end

@implementation VC009_ByteArrayUtilsTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)test001_converDataToHexStringAndHexStringToData {
    NSString *testString = @"72ff63cea198b3edba8f7e0c23acc345050187a0cde5a9872cbab091ab73e553";
    NSData *hexData = [VSCByteArrayUtils dataFromHexString:testString];
    XCTAssertNotNil(hexData);
    XCTAssertTrue(hexData.length > 0);

    NSString *hexString = [VSCByteArrayUtils hexStringFromData:hexData];
    XCTAssertNotNil(hexString);
    XCTAssertEqualObjects(testString, hexString);
}

@end
