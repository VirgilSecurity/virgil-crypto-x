//
//  VSC009_ByteArrayUtils.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import XCTest
import VirgilCrypto

class VSC009_ByteArrayUtils: XCTestCase {
    func test001_converDataToHexStringAndHexStringToData() {
        let testString = "72ff63cea198b3edba8f7e0c23acc345050187a0cde5a9872cbab091ab73e553"
        let hexData = VSCByteArrayUtils.data(fromHexString: testString)!
        XCTAssert(hexData.count > 0)
        
        let hexString = VSCByteArrayUtils.hexString(from: hexData)!
        XCTAssert(testString == hexString)
    }
}
