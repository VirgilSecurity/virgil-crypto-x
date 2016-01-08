//
//  ViewController.m
//  VirgilCypto
//
//  Created by Pavel Gorb on 9/23/15.
//  Copyright (c) 2015 VirgilSecurity. All rights reserved.
//

#import "ViewController.h"
#import "VirgilFoundation.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    VSSVirgilVersion *version = [[VSSVirgilVersion alloc] init];
    NSLog(@"Virgil Version: %@", [version versionString]);
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
}

@end
