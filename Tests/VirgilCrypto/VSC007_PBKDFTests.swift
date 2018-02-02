//
//  VSC007_PBKDFTests.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import XCTest
import VirgilCrypto

class VSC007_PBKDFTests: XCTestCase {
    func test001_createPBKDF() {
        let pbkdf = PBKDF(salt: nil, iterations: 0)
        
        XCTAssertNotNil(pbkdf, "VSCPBKDF instance should be created.")
        
        XCTAssertTrue(pbkdf.iterations > 1024, "VSCPBKDF iterations count should be set to value which is more than 1024.")
        XCTAssertNotNil(pbkdf.salt, "VSCPBKDF salt should be automatically instantiated.")
        XCTAssertEqual(pbkdf.salt.count, kDefaultRandomBytesSize, "VSCPBKDF salt size should be equal the default size.")
        
        XCTAssertEqual(pbkdf.algorithm, VSCPBKDFAlgorithm.PBKDF2, "VSCPBKSD algorithm should be properly set to PBKDF2.")
        
        pbkdf.algorithm = .PBKDF2;
        XCTAssertEqual(pbkdf.algorithm, VSCPBKDFAlgorithm.PBKDF2, "VSCPBKSD algorithm should be properly set to PBKDF2 again.")
        
        XCTAssertNotEqual(pbkdf.hash, VSCPBKDFHash.SHA1, "VSCPBKSD hash should not be set to SHA1 by default.")
        pbkdf.hash = .SHA512;
        XCTAssertEqual(pbkdf.hash, VSCPBKDFHash.SHA512, "VSCPBKSD hash should be properly set to SHA512.")
    }
    
    func test002_keyDerivation() {
        let password = "secret"
        let keySize: size_t = 64
        
        let salt = PBKDF.randomBytes(ofSize: 0)
        
        let pbkdf_a = PBKDF(salt: salt, iterations: 0)
        var key_a: Data? = nil
        do {
            key_a = try pbkdf_a.key(fromPassword: password, size: keySize)
        }
        catch (let error as NSError) {
            XCTFail("VSCPBKDF: key should be derived: \(error.localizedDescription)")
        }
        XCTAssertEqual(key_a!.count, keySize, "VSCPBKDF: key should be generated having the requested size.")
        
        let pbkdf_b = PBKDF(salt: salt, iterations: 0)
        var key_b: Data? = nil
        do {
            key_b = try pbkdf_b.key(fromPassword: password, size: keySize)
        }
        catch (let error as NSError) {
            XCTFail("VSCPBKDF: key should be derived: \(error.localizedDescription)")
        }
        XCTAssertEqual(key_b!.count, keySize, "VSCPBKDF: key should be generated having the requested size.")
        XCTAssertEqual(key_a!, key_b!, "VSCPBKDF: two keys generated independently from the same parameters should match")
        
        let pbkdf_c = PBKDF(salt: nil, iterations: 0)
        var key_c: Data? = nil
        do {
            key_c = try pbkdf_c.key(fromPassword: password, size: keySize)
        }
        catch (let error as NSError) {
            XCTFail("VSCPBKDF: key should be derived: \(error.localizedDescription)")
        }
        XCTAssertEqual(key_c!.count, keySize, "VSCPBKDF: key should be generated having the requested size.")
        XCTAssertNotEqual(key_a!, key_c!, "VSCPBKDF: keys generated with different salt should differ.")
    }
    
    func test003_securityChecks() {
        let pbkdf = PBKDF(salt: nil, iterations: 0)
        
        do {
            try pbkdf.disableRecommendationsCheck()
        }
        catch (let error as NSError) {
            XCTFail("VSCPBKDF: security checks should be disabled: \(error.localizedDescription)")
        }
        
        do {
            try pbkdf.enableRecommendationsCheck()
        }
        catch (let error as NSError) {
            XCTFail("VSCPBKDF: security checks should be enabled: \(error.localizedDescription)")
        }
    }
    
    func test004_algoritmSettings() {
        let pbkdf = PBKDF(salt: nil, iterations: 0)
        var key: Data? = nil
        
        pbkdf.algorithm = .PBKDF2
        do {
            key = try pbkdf.key(fromPassword: "secret", size: 0)
        }
        catch (let error as NSError) {
            XCTFail("VSCPBKDF: key should be derived successfully: \(error.localizedDescription)")
        }
        XCTAssertNotNil(key, "VSCPBKDF: key should be successfully derived.")
    }
}
