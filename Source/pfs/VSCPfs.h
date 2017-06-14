//
//  VSCPfs.h
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "VSCPfsSession.h"
#import "VSCPfsEncryptedMessage.h"
#import "VSCPfsInitiatorPrivateInfo.h"
#import "VSCPfsResponderPublicInfo.h"
#import "VSCPfsResponderPrivateInfo.h"
#import "VSCPfsInitiatorPublicInfo.h"

@interface VSCPfs : NSObject

- (VSCPfsSession * __nonnull)startInitiatorSessionWithInitiatorPrivateInfo:(VSCPfsInitiatorPrivateInfo * __nonnull)initiatorPrivateInfo respondrerPublicInfo:(VSCPfsResponderPublicInfo * __nonnull)respondrerPublicInfo;

- (VSCPfsSession * __nonnull)startResponderSessionWithResponderPrivateInfo:(VSCPfsResponderPrivateInfo * __nonnull)responderPrivateInfo respondrerPublicInfo:(VSCPfsInitiatorPublicInfo * __nonnull)initiatorPublicInfo;

- (VSCPfsEncryptedMessage * __nullable)encryptData:(NSData * __nonnull)data;

- (NSData * __nullable)decryptMessage:(VSCPfsEncryptedMessage * __nonnull)message;

@end
