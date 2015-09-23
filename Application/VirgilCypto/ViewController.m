//
//  ViewController.m
//  VirgilCypto
//
//  Created by Pavel Gorb on 9/23/15.
//  Copyright (c) 2015 VirgilSecurity. All rights reserved.
//

#import "ViewController.h"
#import "VirgilCryptoiOS.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    VCKeyPair *keyPair = [[VCKeyPair alloc] initWithPassword:nil];
    NSLog(@"%@", [[NSString alloc] initWithData:keyPair.publicKey encoding:NSUTF8StringEncoding]);
    NSLog(@"%@", [[NSString alloc] initWithData:keyPair.privateKey encoding:NSUTF8StringEncoding]);
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
