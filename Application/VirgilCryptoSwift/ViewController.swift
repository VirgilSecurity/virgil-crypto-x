//
//  ViewController.swift
//  VirgilCryptoSwift
//
//  Created by Pavel Gorb on 9/23/15.
//  Copyright (c) 2015 VirgilSecurity. All rights reserved.
//

import UIKit
import Foundation

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        
        let keyPair = VCKeyPair(password: nil)
        println(NSString(data: keyPair.publicKey(), encoding: NSUTF8StringEncoding))
        println(NSString(data: keyPair.privateKey(), encoding: NSUTF8StringEncoding))
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }


}

