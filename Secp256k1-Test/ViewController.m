//
//  ViewController.m
//  Secp256k1-Test
//
//  Created by Amit Shah on 2017-12-13.
//  Copyright © 2017 Amit Shah. All rights reserved.
//

#import "ViewController.h"
#import <secp256k1.h>
#import <secp256k1_ecdh.h>
#import <secp256k1_recovery.h>
#import <util.h>
#import <hash_impl.h>
#import <keccak-tiny.h>

@implementation NSString (Hex)

+ (NSString*) hexStringWithData: (unsigned char*) data ofLength: (NSUInteger) len
{
    NSMutableString *tmp = [NSMutableString string];
    for (NSUInteger i=0; i<len; i++)
        [tmp appendFormat:@"%02x", data[i]];
    return [NSString stringWithString:tmp];
}

@end

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    unsigned char key[32];
    int randInt = SecRandomCopyBytes(kSecRandomDefault, 32, key);
    secp256k1_context * ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    int i;
    unsigned char msg[32];
    //unsigned char key[32];
    size_t compressed_output_size = 33;//65;
    unsigned char compressed_output[33];//65];
    
    size_t output_size = 65;
    unsigned char output[65];
    
    
    secp256k1_ecdsa_signature signature;
    secp256k1_ecdsa_signature signatureFromDer;
    secp256k1_pubkey pubkey;
    size_t siglen = 74;
    unsigned char sig[74];
    for (i = 0; i < 32; i++) {
        msg[i] = i + 1;
    }
//    for (i = 0; i < 32; i++) {
//        key[i] = i + 65;
//    }
    
    static const char *inputs[8] = {
        "hello", "abc", "message digest", "secure hash algorithm", "SHA256 is considered to be safe",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "For this sample, this 63-byte string will be used as input data",
        "This is exactly 64 bytes long, not counting the terminating byte"
    };
    static const unsigned char outputs[8][32] = {
        {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55},
        {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad},
        {0xf7, 0x84, 0x6f, 0x55, 0xcf, 0x23, 0xe1, 0x4e, 0xeb, 0xea, 0xb5, 0xb4, 0xe1, 0x55, 0x0c, 0xad, 0x5b, 0x50, 0x9e, 0x33, 0x48, 0xfb, 0xc4, 0xef, 0xa3, 0xa1, 0x41, 0x3d, 0x39, 0x3c, 0xb6, 0x50},
        {0xf3, 0x0c, 0xeb, 0x2b, 0xb2, 0x82, 0x9e, 0x79, 0xe4, 0xca, 0x97, 0x53, 0xd3, 0x5a, 0x8e, 0xcc, 0x00, 0x26, 0x2d, 0x16, 0x4c, 0xc0, 0x77, 0x08, 0x02, 0x95, 0x38, 0x1c, 0xbd, 0x64, 0x3f, 0x0d},
        {0x68, 0x19, 0xd9, 0x15, 0xc7, 0x3f, 0x4d, 0x1e, 0x77, 0xe4, 0xe1, 0xb5, 0x2d, 0x1f, 0xa0, 0xf9, 0xcf, 0x9b, 0xea, 0xea, 0xd3, 0x93, 0x9f, 0x15, 0x87, 0x4b, 0xd9, 0x88, 0xe2, 0xa2, 0x36, 0x30},
        {0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1},
        {0xf0, 0x8a, 0x78, 0xcb, 0xba, 0xee, 0x08, 0x2b, 0x05, 0x2a, 0xe0, 0x70, 0x8f, 0x32, 0xfa, 0x1e, 0x50, 0xc5, 0xc4, 0x21, 0xaa, 0x77, 0x2b, 0xa5, 0xdb, 0xb4, 0x06, 0xa2, 0xea, 0x6b, 0xe3, 0x42},
        {0xab, 0x64, 0xef, 0xf7, 0xe8, 0x8e, 0x2e, 0x46, 0x16, 0x5e, 0x29, 0xf2, 0xbc, 0xe4, 0x18, 0x26, 0xbd, 0x4c, 0x7b, 0x35, 0x52, 0xf6, 0xb3, 0x82, 0xa9, 0xe7, 0xd3, 0xaf, 0x47, 0xc2, 0x45, 0xf8}
    };
    
    
    //Test keccak-tiny implementation
    uint8_t hashResult[32];
//    sha3_256(hashResult, 32, (uint8_t *)inputs[0] , strlen(inputs[0]));
    
    keccack_256(hashResult, 32, (uint8_t *)inputs[0] , strlen(inputs[0]));
    //https://emn178.github.io/online-tools/keccak_256.html
    //1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
    NSString * hashed = [NSString hexStringWithData:hashResult ofLength:32];
    
    if( [hashed isEqualToString: @"1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"]){
        NSLog(@"%@ hash equals hello hashing from https://emn178.github.io/online-tools/keccak_256.html\r\n", hashed);
    }
    
    
    //testing secp2561 library sha256 implementation (it matches)
    //https://emn178.github.io/online-tools/sha256.html
    unsigned char out[32];
    int k = 0;
    secp256k1_sha256 hasher;
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, (const unsigned char*)(inputs[k]), strlen(inputs[k]));
    secp256k1_sha256_finalize(&hasher, out);
    int cmp = memcmp(out, outputs[k], 32);
    
    secp256k1_ecdsa_sign(ctx, &signature, msg, key, NULL, NULL);
    secp256k1_ecdsa_signature_serialize_der(ctx, sig, &siglen, &signature);
    
    //HS - https://bitcoin.stackexchange.com/questions/2376/ecdsa-r-s-encoding-as-a-signature
    //3045, then we get S (0221) then we get R (0220), for V check both
    NSString * hs = [NSString hexStringWithData:sig ofLength:siglen];
    
    NSString * sec =[NSString hexStringWithData:key ofLength:32];
   
   
    
    secp256k1_ecdsa_signature_parse_der(ctx, &signatureFromDer, sig, siglen);
    
    
    int v = secp256k1_ec_pubkey_create(ctx, &pubkey, key);
    
    secp256k1_ec_pubkey_serialize(ctx,
                                  compressed_output,
                                  &compressed_output_size,
                                  &pubkey,
                                  SECP256K1_EC_COMPRESSED
                                  );

    secp256k1_ec_pubkey_serialize(ctx,
                                  output,
                                  &output_size,
                                  &pubkey,
                                  SECP256K1_EC_UNCOMPRESSED
                                  );

    //https://bitcoin.stackexchange.com/questions/3059/what-is-a-compressed-bitcoin-key
    //https://brainwalletx.github.io/#generator to validate sec == public key
    NSString * compressed_pk =[NSString hexStringWithData:compressed_output ofLength:33];
    NSString * pk =[NSString hexStringWithData:output ofLength:65];
    
    NSLog(@"return value of pub key = %d, key:%@, compressed_pk:%@, pk:%@", v,sec, compressed_pk,pk);
    
    v= secp256k1_ecdsa_verify(ctx, &signature, msg, &pubkey);
    NSLog(@"return value of signature verification = %d", v);

    v= secp256k1_ecdsa_verify(ctx, &signatureFromDer, msg, &pubkey);
    NSLog(@"return value of signature from DER verification = %d", v);

    //secp256k1_ecdsa_signature_serialize_der(ctx, signature, &siglen, &signature)

    // Do any additional setup after loading the view, typically from a nib.
    secp256k1_context_destroy(ctx);
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
