// Test executable for a fresh CI user's file keychain. The key never leaves
// the Keychain. Allow the same node executable that loads the production addon.
#import <Foundation/Foundation.h>
#import <Security/Security.h>

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 3) return 2;
        NSString *label = @(argv[1]);
        SecTrustedApplicationRef node = NULL;
        if (SecTrustedApplicationCreateFromPath(argv[2], &node)) return 3;
        SecAccessRef access = NULL;
        OSStatus result = SecAccessCreate((__bridge CFStringRef)label,
            (__bridge CFArrayRef)@[(__bridge id)node], &access);
        if (result) return 4;
        NSDictionary *attributes = @{
            (__bridge id)kSecAttrKeyType:(__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
            (__bridge id)kSecAttrKeySizeInBits:@256,
            (__bridge id)kSecPrivateKeyAttrs:@{
                (__bridge id)kSecAttrIsPermanent:@YES,
                (__bridge id)kSecAttrIsExtractable:@NO,
                (__bridge id)kSecAttrAccess:(__bridge id)access,
                (__bridge id)kSecAttrLabel:label
            }
        };
        SecKeyRef key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes,NULL);
        if (!key) return 5;
        SecKeyRef publicKey = SecKeyCopyPublicKey(key);
        if (!publicKey) return 6;
        NSData *point = CFBridgingRelease(SecKeyCopyExternalRepresentation(publicKey,NULL));
        if (point.length != 65) return 7;
        puts([point base64EncodedStringWithOptions:0].UTF8String);
        CFRelease(publicKey); CFRelease(key); CFRelease(access); CFRelease(node);
    }
    return 0;
}
