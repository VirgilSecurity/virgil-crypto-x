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

- (VSCPfsSession * __nullable)startInitiatorSessionWithInitiatorPrivateInfo:(VSCPfsInitiatorPrivateInfo * __nonnull)initiatorPrivateInfo respondrerPublicInfo:(VSCPfsResponderPublicInfo * __nonnull)respondrerPublicInfo additionalData:(NSData * __nullable)additionalData;

- (VSCPfsSession * __nullable)startResponderSessionWithResponderPrivateInfo:(VSCPfsResponderPrivateInfo * __nonnull)responderPrivateInfo respondrerPublicInfo:(VSCPfsInitiatorPublicInfo * __nonnull)initiatorPublicInfo additionalData:(NSData * __nullable)additionalData;

- (VSCPfsEncryptedMessage * __nullable)encryptData:(NSData * __nonnull)data;

- (NSData * __nullable)decryptMessage:(VSCPfsEncryptedMessage * __nonnull)message;

@property (nonatomic) VSCPfsSession * __nullable session;

@end
