//
//  VSCBaseCryptor.m
//  VirgilCypto
//
//  Created by Pavel Gorb on 2/23/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import "VSCBaseCryptor.h"
#import "VSCBaseCryptor_Private.h"
#import "VSCByteArrayUtils_Private.h"
#import <virgil/crypto/VirgilCipherBase.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilCipherBase;

NSString *const kVSCBaseCryptorErrorDomain = @"VSCBaseCryptorErrorDomain";

@interface VSCBaseCryptor ()

- (VirgilCipherBase *)cryptor;

@end

@implementation VSCBaseCryptor

@synthesize llCryptor = _llCryptor;

- (instancetype)init {
    self = [super init];
    if (self == nil) {
        return nil;
    }
    
    [self initializeCryptor];
    return self;
}

- (void)initializeCryptor {
    if (self.llCryptor != NULL) {
        // llCryptor has been initialized already.
        return;
    }
    
    try {
        self.llCryptor = new VirgilCipherBase();
    }
    catch(...) {
        self.llCryptor = NULL;
    }
}

- (VirgilCipherBase *)cryptor {
    if (self.llCryptor == NULL) {
        return NULL;
    }
    
    return static_cast<VirgilCipherBase *>(self.llCryptor);
}

- (void)addKeyRecipient:(NSData *)recipientId publicKey:(NSData *)publicKey {
    [self addKeyRecipient:recipientId publicKey:publicKey error:nil];
}

- (BOOL)addKeyRecipient:(NSData * __nonnull)recipientId publicKey:(NSData * __nonnull)publicKey error:(NSError * __nullable * __nullable)error {
    if (recipientId.length == 0 || publicKey.length == 0) {
        // Can't add recipient.
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1000 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to add key recipient. Required arguments are missing." }];
        }
        return NO;
    }
    
    BOOL success;
    try {
        if ([self cryptor] != NULL) {
            const VirgilByteArray &recId = [VSCByteArrayUtils convertVirgilByteArrayFromData:recipientId];
            const VirgilByteArray &pKeyBytes = [VSCByteArrayUtils convertVirgilByteArrayFromData:publicKey];
            [self cryptor]->addKeyRecipient(recId, pKeyBytes);
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1001 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to add key recipient. Cryptor is not initialized properly." }];
            }
            success = NO;
        }
        
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during adding key recipient.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1002 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1003 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during adding key recipient." }];
        }
        success = NO;
    }
    
    return success;
}

- (void)removeKeyRecipient:(NSData *)recipientId {
    [self removeKeyRecipient:recipientId error:nil];
}

- (BOOL)removeKeyRecipient:(NSData *)recipientId error:(NSError **)error {
    if (recipientId.length == 0) {
        // Can't remove recipient
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1003 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to remove key recipient. Required argument is missing." }];
        }
        return NO;
    }
    
    BOOL success;
    try {
        if ([self cryptor] != NULL) {
            const VirgilByteArray &recId = [VSCByteArrayUtils convertVirgilByteArrayFromData:recipientId];
            [self cryptor]->removeKeyRecipient(recId);
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1004 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to remove key recipient. Cryptor is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during removing key recipient.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1005 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1006 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during removing key recipient." }];
        }
        success = NO;
    }
    
    return success;
}

- (BOOL)isKeyRecipientExists:(NSData *__nonnull)recipientId {
    if (!recipientId || recipientId.length == 0) {
        return NO;
    }

    VirgilByteArray virgilRecipientId = [VSCByteArrayUtils convertVirgilByteArrayFromData:recipientId];
    return [self cryptor]->keyRecipientExists(virgilRecipientId);
}

- (void)addPasswordRecipient:(NSString *)password {
    [self addPasswordRecipient:password error:nil];
}

- (BOOL)addPasswordRecipient:(NSString *)password error:(NSError **)error {
    if (password.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1007 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to add password recipient. Required argument is missing." }];
        }
        return NO;
    }
    
    BOOL success;
    try {
        if ([self cryptor] != NULL) {
            const VirgilByteArray &vPass = [VSCByteArrayUtils convertVirgilByteArrayFromString:password];
            [self cryptor]->addPasswordRecipient(vPass);
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1008 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to add password recipient. Cryptor is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during adding password recipient.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1009 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1010 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during adding password recipient." }];
        }
        success = NO;
    }
    
    return success;
}

- (void)removePasswordRecipient:(NSString *)password {
    [self removePasswordRecipient:password error:nil];
}

- (BOOL)removePasswordRecipient:(NSString *)password error:(NSError **)error {
    if (password.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1011 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to remove password recipient. Required argument is missing." }];
        }
        return NO;
    }
    
    BOOL success;
    try {
        if ([self cryptor] != NULL) {
            const VirgilByteArray &vPass = [VSCByteArrayUtils convertVirgilByteArrayFromString:password];
            [self cryptor]->removePasswordRecipient(vPass);
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1012 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to remove password recipient. Cryptor is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during removing password recipient.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1013 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1014 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during removing password recipient." }];
        }
        success = NO;
    }
    return success;
}

- (void)removeAllRecipients {
    [self removeAllRecipientsWithError:nil];
}

- (BOOL)removeAllRecipientsWithError:(NSError **)error {
    if ([self cryptor] == NULL) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1015 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to remove all recipients. Cryptor is not initialized properly." }];
        }
        return NO;
    }
    
    BOOL success = NO;
    try {
        [self cryptor]->removeAllRecipients();
        if (error) {
            *error = nil;
        }
        success = YES;
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during removing all recipients.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1016 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1017 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during removing all recipients." }];
        }
        success = NO;
    }
    return success;
}

- (NSData *)contentInfo {
    return [self contentInfoWithError:nil];
}

- (NSData *)contentInfoWithError:(NSError **)error {
    NSData* contentInfo = nil;
    try {
        if ([self cryptor] != NULL) {
            const VirgilByteArray &content = [self cryptor]->getContentInfo();
            contentInfo = [NSData dataWithBytes:content.data() length:content.size()];
            if (error) {
                *error = nil;
            }
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1018 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to get content info. Cryptor is not initialized properly." }];
            }
            contentInfo = nil;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during getting content info.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1019 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        contentInfo = nil;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1020 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during getting content info." }];
        }
        contentInfo = nil;
    }
    return contentInfo;
}

- (void)setContentInfo:(NSData *) contentInfo {
    [self setContentInfo:contentInfo error:nil];
}

- (BOOL)setContentInfo:(NSData *)contentInfo error:(NSError **)error {
    if (contentInfo.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1021 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to set content info. Required argument is missing." }];
        }
        return NO;
    }
    
    BOOL success;
    try {
        if ([self cryptor] != NULL) {
            const VirgilByteArray &contentInfoBytes = [VSCByteArrayUtils convertVirgilByteArrayFromData:contentInfo];
            [self cryptor]->setContentInfo(contentInfoBytes);
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1022 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to set content info. Cryptor is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during setting content info.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1023 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1024 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during setting content info." }];
        }
        success = NO;
    }
    return success;
}

- (size_t)contentInfoSizeInData:(NSData *)data error:(NSError **)error {
    if (data.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1025 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to calculate size of the content info. Required argument is missing." }];
        }
        return 0;
    }
    
    size_t size = 0;
    try {
        if ([self cryptor] != NULL) {
            const VirgilByteArray &bytes = [VSCByteArrayUtils convertVirgilByteArrayFromData:data];
            size = [self cryptor]->defineContentInfoSize(bytes);
            if (error) {
                *error = nil;
            }
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1026 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to calculate size of the content info. Cryptor is not initialized properly." }];
            }
            size = 0;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during calculating the size of the content info.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1027 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        size = 0;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1028 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during calculating the size of the content info." }];
        }
        size = 0;
    }
    return size;
}

- (BOOL)setInt:(int)value forKey:(NSString *)key error:(NSError **)error {
    if (key.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1029 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to set custom int parameter. Required argument is missing." }];
        }
        return NO;
    }
    
    BOOL success;
    try {
        if ([self cryptor] != NULL) {
            const VirgilByteArray &strKey = [VSCByteArrayUtils convertVirgilByteArrayFromString:key];
            [self cryptor]->customParams().setInteger(strKey, value);
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1030 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to set custom int parameter. Cryptor is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during setting custom int parameter.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1031 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1032 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during setting custom int parameter." }];
        }
        success = NO;
    }
    return success;
}

- (int)intForKey:(NSString *)key error:(NSError **)error {
    if (key.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1033 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to get custom int parameter. Required argument is missing." }];
        }
        return 0;
    }
    
    int value = 0;
    try {
        if ([self cryptor] != NULL) {
            const VirgilByteArray &vStrKey = [VSCByteArrayUtils convertVirgilByteArrayFromString:key];
            value = [self cryptor]->customParams().getInteger(vStrKey);
            if (error) {
                *error = nil;
            }
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1034 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to get custom int parameter. Cryptor is not initialized properly." }];
            }
            value = 0;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during getting custom int parameter.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1035 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        value = 0;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1036 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during getting custom int parameter." }];
        }
        value = 0;
    }
    return value;
}

- (BOOL)removeIntForKey:(NSString *)key error:(NSError **)error {
    if (key.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1037 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to remove custom int parameter. Required argument is missing." }];
        }
        return NO;
    }
    
    BOOL success;
    try {
        if ([self cryptor] != NULL) {
            const VirgilByteArray &vStrKey = [VSCByteArrayUtils convertVirgilByteArrayFromString:key];
            [self cryptor]->customParams().removeInteger(vStrKey);
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1038 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to remove custom int parameter. Cryptor is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during removing custom int parameter.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1039 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1040 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during removing custom int parameter." }];
        }
        success = NO;
    }
    return success;
}

- (BOOL)setString:(NSString *)value forKey:(NSString *)key error:(NSError **)error {
    if (key.length == 0 || value.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1041 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to set custom string parameter. At least one of the required arguments is missing." }];
        }
        return NO;
    }
    
    BOOL success = NO;
    try {
        if ([self cryptor] != NULL) {
            const VirgilByteArray &vStrKey = [VSCByteArrayUtils convertVirgilByteArrayFromString:key];
            const VirgilByteArray &vStrVal = [VSCByteArrayUtils convertVirgilByteArrayFromString:value];

            [self cryptor]->customParams().setString(vStrKey, vStrVal);
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1042 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to set custom string parameter. Cryptor is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during setting custom string parameter.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1043 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1044 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during setting custom string parameter." }];
        }
        success = NO;
    }
    return success;
}

- (NSString *)stringForKey:(NSString *)key error:(NSError **)error {
    if (key.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1045 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to get custom string parameter. Required argument is missing." }];
        }
        return nil;
    }
    
    NSString *value = nil;
    try {
        if ([self cryptor] != NULL) {
            const VirgilByteArray &vStrKey = [VSCByteArrayUtils convertVirgilByteArrayFromString:key];
            const VirgilByteArray &vStrVal = [self cryptor]->customParams().getString(vStrKey);
            std::string str = virgil::crypto::bytes2str(vStrVal);
            value = [[NSString alloc] initWithCString:str.c_str() encoding:NSUTF8StringEncoding];
            if (error) {
                *error = nil;
            }
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1046 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to get custom string parameter. Cryptor is not initialized properly." }];
            }
            value = nil;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during getting custom string parameter.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1047 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        value = nil;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1048 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during getting custom string parameter." }];
        }
        value = nil;
    }
    return value;
}

- (BOOL)removeStringForKey:(NSString *)key error:(NSError **)error {
    if (key.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1049 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to remove custom string parameter. Required argument is missing." }];
        }
        return NO;
    }
    
    BOOL success = NO;
    try {
        if ([self cryptor] != NULL) {
            const VirgilByteArray &vStrKey = [VSCByteArrayUtils convertVirgilByteArrayFromString:key];
            [self cryptor]->customParams().removeString(vStrKey);
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1050 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to remove custom string parameter. Cryptor is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during removing custom string parameter.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1051 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1052 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during removing custom string parameter." }];
        }
        success = NO;
    }
    return success;
}

- (BOOL)setData:(NSData *)value forKey:(NSString *)key error:(NSError **)error {
    if (key.length == 0 || value.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1053 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to set custom data parameter. At least one of the required arguments is missing." }];
        }
        return NO;
    }
    
    BOOL success = NO;
    try {
        if ([self cryptor] != NULL) {
            const VirgilByteArray &vStrKey = [VSCByteArrayUtils convertVirgilByteArrayFromString:key];
            const VirgilByteArray &vBytes = [VSCByteArrayUtils convertVirgilByteArrayFromData:value];
            [self cryptor]->customParams().setData(vStrKey, vBytes);

            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1054 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to set custom data parameter. Cryptor is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during setting custom data parameter.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1055 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1056 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during setting custom data parameter." }];
        }
        success = NO;
    }
    return success;
}

- (NSData *)dataForKey:(NSString *)key error:(NSError **)error {
    if (key.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1057 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to get custom data parameter. Required argument is missing." }];
        }
        return nil;
    }
    
    NSData *value = nil;
    try {
        if ([self cryptor] != NULL) {
            const VirgilByteArray &vStrKey = [VSCByteArrayUtils convertVirgilByteArrayFromString:key];
            const VirgilByteArray &dataVal = [self cryptor]->customParams().getData(vStrKey);
            value = [[NSData alloc] initWithBytes:dataVal.data() length:dataVal.size()];
            if (error) {
                *error = nil;
            }
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1058 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to get custom data parameter. Cryptor is not initialized properly." }];
            }
            value = nil;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during getting custom data parameter.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1059 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        value = nil;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1060 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during getting custom data parameter." }];
        }
        value = nil;
    }
    return value;
}

- (BOOL)removeDataForKey:(NSString *)key error:(NSError **)error {
    if (key.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1061 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to remove custom data parameter. Required argument is missing." }];
        }
        return NO;
    }
    
    BOOL success;
    try {
        if ([self cryptor] != NULL) {
            const VirgilByteArray &vStrKey = [VSCByteArrayUtils convertVirgilByteArrayFromString:key];
            [self cryptor]->customParams().removeData(vStrKey);
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1062 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to remove custom data parameter. Cryptor is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during removing custom data parameter.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1063 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1064 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during removing custom data parameter." }];
        }
        success = NO;
    }
    return success;
}

- (BOOL)isEmptyCustomParametersWithError:(NSError * __nullable * __nullable)error {
    if ([self cryptor] == NULL) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1065 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to check for emptiness of the custom parameters. Cryptor is not initialized properly." }];
        }
        return YES;
    }
    
    BOOL success;
    try {
        bool empty = [self cryptor]->customParams().isEmpty();
        success = empty;
        if (error) {
            *error = nil;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during checking for emptiness of the custom parameters.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1066 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = YES;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1067 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during checking for emptiness of the custom parameters." }];
        }
        success = YES;
    }
    return success;
}

- (BOOL)clearCustomParametersWithError:(NSError * __nullable * __nullable)error {
    if ([self cryptor] == NULL) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1068 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to clear the custom parameters. Cryptor is not initialized properly." }];
        }
        return NO;
    }
    
    BOOL success;
    try {
        [self cryptor]->customParams().clear();
        success = YES;
        if (error) {
            *error = nil;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during clearing the custom parameters.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1069 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = YES;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCryptorErrorDomain code:-1070 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during clearing the custom parameters." }];
        }
        success = YES;
    }
    return success;
}

@end
