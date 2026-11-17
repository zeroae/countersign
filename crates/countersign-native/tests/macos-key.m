// Disposable provider fixture, compiled separately from the product. Create
// the private key under the same Node application's Keychain ACL that will
// execute the product addon. Return the public point only.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <node_api.h>

static napi_value generate(napi_env env, napi_callback_info info) {
    @autoreleasepool {
        size_t count = 2;
        napi_value argv[2];
        if (napi_get_cb_info(env, info, &count, argv, NULL, NULL) != napi_ok || count != 2)
            goto error;
        char text[128];
        size_t length;
        if (napi_get_value_string_utf8(env, argv[0], text, sizeof(text), &length) != napi_ok ||
            length == 0 || length >= sizeof(text) - 1) goto error;
        NSString *label = [NSString stringWithUTF8String:text];
        if (![label hasPrefix:@"CountersignCI-"]) goto error;
        char alg[8];
        if (napi_get_value_string_utf8(env, argv[1], alg, sizeof(alg), &length) != napi_ok) goto error;
        BOOL rsa = !strcmp(alg,"rsa");
        NSNumber *bits = rsa ? @2048 : (!strcmp(alg,"p384") ? @384 : @256);
        NSDictionary *attributes = @{
            (__bridge id)kSecAttrKeyType:(__bridge id)(rsa ? kSecAttrKeyTypeRSA : kSecAttrKeyTypeECSECPrimeRandom),
            (__bridge id)kSecAttrKeySizeInBits:bits,
            (__bridge id)kSecPrivateKeyAttrs:@{
                (__bridge id)kSecAttrIsPermanent:@YES,
                (__bridge id)kSecAttrIsExtractable:@NO,
                (__bridge id)kSecAttrLabel:label
            }
        };
        SecKeyRef key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes,NULL);
        if (!key) goto error;
        SecKeyRef publicKey = SecKeyCopyPublicKey(key);
        CFRelease(key);
        if (!publicKey) goto error;
        NSData *point = CFBridgingRelease(SecKeyCopyExternalRepresentation(publicKey,NULL));
        CFRelease(publicKey);
        if (point.length == 0) goto error;
        napi_value result;
        if (napi_create_string_utf8(env, [point base64EncodedStringWithOptions:0].UTF8String,
                                    NAPI_AUTO_LENGTH, &result) == napi_ok) return result;
    }
error:
    napi_throw_error(env, NULL, "create isolated macOS fixture key");
    return NULL;
}

static napi_value no_ui(napi_env env, napi_callback_info info) {
    if (SecKeychainSetUserInteractionAllowed(false) != errSecSuccess) {
        napi_throw_error(env, NULL, "could not disable test account prompts");
    }
    return NULL;
}

NAPI_MODULE_INIT() {
    napi_property_descriptor functions[] = {
        {"generateWebsiteKey", NULL, generate, NULL, NULL, NULL, napi_default, NULL},
        {"denyInteraction", NULL, no_ui, NULL, NULL, NULL, napi_default, NULL},
    };
    if (napi_define_properties(env, exports, 2, functions) != napi_ok) return NULL;
    return exports;
}
