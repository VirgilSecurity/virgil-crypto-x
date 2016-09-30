//
//  VC007_PBKDFTests.m
//  VirgilCypto
//
//  Created by Pavel Gorb on 4/27/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import <XCTest/XCTest.h>
#import <Foundation/Foundation.h>

#import "VSCPBKDF.h"

@interface VC007_PBKDFTests : XCTestCase

@end

@implementation VC007_PBKDFTests

- (void)test001_createPBKDF {
    VSCPBKDF *pbkdf = [[VSCPBKDF alloc] initWithSalt:nil iterations:0];
    XCTAssertNotNil(pbkdf, @"VSCPBKDF instance should be created.");
    
    XCTAssertTrue(pbkdf.iterations > 1024, @"VSCPBKDF iterations count should be set to value which is more than 1024.");
    XCTAssertNotNil(pbkdf.salt, @"VSCPBKDF salt should be automatically instantiated.");
    XCTAssertEqual(pbkdf.salt.length, kVSSDefaultRandomBytesSize, @"VSCPBKDF salt size should be equal the default size.");
    
    XCTAssertEqual(pbkdf.algorithm, VSSPBKDFAlgorithmPBKDF2, @"VSSPBKSD algorithm should be properly set to PBKDF2.");
    pbkdf.algorithm = VSSPBKDFAlgorithmPBKDF2;
    XCTAssertEqual(pbkdf.algorithm, VSSPBKDFAlgorithmPBKDF2, @"VSSPBKSD algorithm should be properly set to PBKDF2 again.");
    
    XCTAssertNotEqual(pbkdf.hash, 0, @"VSSPBKSD hash should not be set to 0 by default.");
    XCTAssertNotEqual(pbkdf.hash, VSSPBKDFHashSHA1, @"VSSPBKSD hash should not be set to SHA1 by default.");
    pbkdf.hash = VSSPBKDFHashSHA512;
    XCTAssertEqual(pbkdf.hash, VSSPBKDFHashSHA512, @"VSSPBKSD hash should be properly set to SHA512.");
}

- (void)test002_keyDerivation {
    NSString *password = @"secret";
    size_t keySize = 64;
    NSError *error = nil;
    
    NSData *salt = [VSCPBKDF randomBytesOfSize:0];
    
    VSCPBKDF *pbkdf_a = [[VSCPBKDF alloc] initWithSalt:salt iterations:0];
    NSData *key_a = [pbkdf_a keyFromPassword:password size:keySize error:&error];
    XCTAssertNil(error, @"VSCPBKDF: key should be successfully derived from the password.");
    XCTAssertNotNil(key_a, @"VSCPBKDF: key should contain actual data after the derivation.");
    XCTAssertEqual(key_a.length, keySize, @"VSCPBKDF: key should be generated having the requested size.");
    
    VSCPBKDF *pbkdf_b = [[VSCPBKDF alloc] initWithSalt:salt iterations:0];
    NSData *key_b = [pbkdf_b keyFromPassword:password size:keySize error:&error];
    XCTAssertNil(error, @"VSCPBKDF: key should be successfully derived from the password.");
    XCTAssertNotNil(key_b, @"VSCPBKDF: key should contain actual data after the derivation.");
    XCTAssertEqual(key_b.length, keySize, @"VSCPBKDF: key should be generated having the requested size.");
    
    XCTAssertEqualObjects(key_a, key_b, @"VSCPBKDF: two keys generated independently from the same parameters should match");
    
    VSCPBKDF *pbkdf_c = [[VSCPBKDF alloc] initWithSalt:nil iterations:0];
    NSData *key_c = [pbkdf_c keyFromPassword:password size:keySize error:&error];
    XCTAssertNil(error, @"VSCPBKDF: key should be successfully derived from the password.");
    XCTAssertNotNil(key_a, @"VSCPBKDF: key should contain actual data after the derivation.");
    XCTAssertEqual(key_a.length, keySize, @"VSCPBKDF: key should be generated having the requested size.");
    
    XCTAssertNotEqualObjects(key_a, key_c, @"VSCPBKDF: keys generated with different salt should differ.");
}

- (void)test003_securityChecks {
    VSCPBKDF *pbkdf = [[VSCPBKDF alloc] initWithSalt:nil iterations:0];
    NSError *error = nil;

    BOOL ok = [pbkdf disableRecommendationsCheckWithError:&error];
    XCTAssertTrue(ok, @"VSCPBKDF: security checks should be successfully disabled.");
    XCTAssertNil(error, @"VSCPBKDF: errors should not happen during disabling of the security checks.");
    
    ok = [pbkdf enableRecommendationsCheckWithError:&error];
    XCTAssertTrue(ok, @"VSCPBKDF: security checks should be successfully enabled.");
    XCTAssertNil(error, @"VSCPBKDF: errors should not happen during enabling of the security checks.");
}

- (void)test004_algoritmSettings {
    VSCPBKDF *pbkdf = [[VSCPBKDF alloc] initWithSalt:nil iterations:0];
    NSError *error = nil;
    
    pbkdf.algorithm = VSSPBKDFAlgorithmPBKDF2;
    NSData *key_1 = [pbkdf keyFromPassword:@"secret" size:0 error:&error];
    XCTAssertNil(error, @"VSCPBKDF: key should be derived successfully.");
    XCTAssertNotNil(key_1, @"VSCPBKDF: key should be derived from the password.");
}

@end
