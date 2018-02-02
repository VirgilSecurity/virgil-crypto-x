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

/**
 Class for main PFS operations
 */
NS_SWIFT_NAME(Pfs)
@interface VSCPfs : NSObject

/**
 Starts initiator session.

 @param initiatorPrivateInfo Initiator Private Info
 @param respondrerPublicInfo Responder Public Info
 @param additionalData Additional data for authentication
 @return initialized Pfs Session
 */
- (VSCPfsSession * __nullable)startInitiatorSessionWithInitiatorPrivateInfo:(VSCPfsInitiatorPrivateInfo * __nonnull)initiatorPrivateInfo respondrerPublicInfo:(VSCPfsResponderPublicInfo * __nonnull)respondrerPublicInfo additionalData:(NSData * __nullable)additionalData;

/**
 Starts responder session.

 @param responderPrivateInfo Responder Private Info
 @param initiatorPublicInfo Initiator Public Info
 @param additionalData Additional data for authentication
 @return Pfs Session
 */
- (VSCPfsSession * __nullable)startResponderSessionWithResponderPrivateInfo:(VSCPfsResponderPrivateInfo * __nonnull)responderPrivateInfo initiatorPublicInfo:(VSCPfsInitiatorPublicInfo * __nonnull)initiatorPublicInfo additionalData:(NSData * __nullable)additionalData;

/**
 Encrypts data

 @param data Data to encrypt
 @return Encrypted message
 */
- (VSCPfsEncryptedMessage * __nullable)encryptData:(NSData * __nonnull)data;

/**
 Decrypts data

 @param message message to decrypt
 @return Decrypted
 */
- (NSData * __nullable)decryptMessage:(VSCPfsEncryptedMessage * __nonnull)message;

/**
 Underlying PFS session
 */
@property (nonatomic) VSCPfsSession * __nullable session;

@end
