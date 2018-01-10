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


#import "Transaction.h"
#import "tommath.h"

@implementation NSString (Hex)

+ (NSString*) hexStringWithData: (unsigned char*) data ofLength: (NSUInteger) len
{
    NSMutableString *tmp = [NSMutableString string];
    for (NSUInteger i=0; i<len; i++)
        [tmp appendFormat:@"%02x", data[i]];
    return [NSString stringWithString:tmp];
}

- (NSData *)dataFromHexString {
    
    const char *chars = [self UTF8String];
    int i = 0, len = self.length;
    
    NSMutableData *data = [NSMutableData dataWithCapacity:len / 2];
    char byteChars[3] = {'\0','\0','\0'};
    unsigned long wholeByte;
    
    while (i < len) {
        byteChars[0] = chars[i++];
        byteChars[1] = chars[i++];
        wholeByte = strtoul(byteChars, NULL, 16);
        [data appendBytes:&wholeByte length:1];
    }
    //unsigned char *bytePtr = (unsigned char *)[data bytes];
    return data;
}


@end

@interface ViewController ()

@end

//uncomment to test random key generation with kSecRandom
//#define RANDOM_KEY

//TODO, we want to wrap this to change our nonce on demand
static int custom_nonce_function_rfc6979(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter){

    return secp256k1_nonce_function_rfc6979(nonce32, msg32, key32, algo16, data, counter);
}


@implementation ViewController


- (void)viewDidLoad {
    [super viewDidLoad];
   

    Transaction* t = [[Transaction alloc] init];
    mp_int gasLimit;
    mp_init(&gasLimit);
    mp_set(&gasLimit, 1000);
    t.gasLimit = gasLimit;
    
    mp_int gasPrice;
    mp_init(&gasPrice);
    mp_set(&gasPrice, 100);
    t.gasPrice = gasPrice;
    
    mp_int nonce;
    mp_init(&nonce);
    mp_set(&nonce, 2);
    t.nonce = nonce;
    
    mp_int value;
    mp_init(&value);
    mp_set(&value, 120);
    t.value = value;
    
    uint8_t * address = (uint8_t*)[@"1f36f546477cda21bf2296c50976f2740247906f" dataFromHexString].bytes;
    
    t.toAddress = address;

    
    //NSData * d = [t serialize];
    NSData * transactionEncoding = [t signSerialize];
    //const char *bytes = [d bytes];

    NSLog(@"%@",[NSString hexStringWithData:transactionEncoding.bytes ofLength:transactionEncoding.length]);
    
    uint8_t hashedTransaction[32];
    
    //TODO for signing we set chainId = 0, we only need the first 6 params (no r,s,v) -> keccak hash -> sign 
    keccack_256(hashedTransaction, 32, (uint8_t*)transactionEncoding.bytes , transactionEncoding.length);
    
    NSLog(@"%@", [NSString hexStringWithData:hashedTransaction ofLength:32]);
    
    
    
    
    unsigned char key[32];
#ifdef RANDOM_KEY
    NSLog(@"generating random secret");
    int randInt = SecRandomCopyBytes(kSecRandomDefault, 32, key);
#else
    NSLog(@"copying secret");
    memcpy(key,[@"e331b6d69882b4cb4ea581d88e0b604039a3de5967688d3dcffdd2270c0fd109" dataFromHexString].bytes,
           32);
#endif
    
   
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
    //convert hello to hex then apply keccack, it works.
    uint8_t vv[5] ={0x68,0x65,0x6c,0x6c,0x6f};
    keccack_256(hashResult, 32, vv , 5);
    
    //https://emn178.github.io/online-tools/keccak_256.html
    //1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
    NSString * hashed = [NSString hexStringWithData:hashResult ofLength:32];
    
    if( [hashed isEqualToString: @"1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"]){
        NSLog(@"%@ hash equals hello hashing from https://emn178.github.io/online-tools/keccak_256.html\r\n", hashed);
    }
    
    keccack_256(hashResult, 32, (uint8_t*)inputs[0] , strlen(inputs[0]));
    
    //https://emn178.github.io/online-tools/keccak_256.html
    //1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
    hashed = [NSString hexStringWithData:hashResult ofLength:32];
    
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
    
   
    secp256k1_ecdsa_sign(ctx, &signature, hashedTransaction, key, custom_nonce_function_rfc6979, NULL);
    secp256k1_ecdsa_signature_serialize_der(ctx, sig, &siglen, &signature);
    
    uint8_t r[32];
    uint8_t s[32];
    
    der_sig_parse(r,s, sig, siglen);
    
    
//    t.s = &s[0] ;
//    t.r = &r[0] ;
    
    t.s = &s[0];
    t.r = &r[0];
    
    NSLog(@"SIG R: %@---", [NSString hexStringWithData:t.r ofLength:32] );
    NSLog(@"SIG S: %@---", [NSString hexStringWithData:t.s ofLength:32] );
    
    NSData * d = [t serialize: true];
    const char *bytes = [d bytes];
    
    NSLog(@"hashed signed transaction:%@----",[NSString hexStringWithData:d.bytes ofLength:d.length]);
    
    
   
    
    
    
    
    
    //HS - https://bitcoin.stackexchange.com/questions/2376/ecdsa-r-s-encoding-as-a-signature
    //3045, then we get S (022100) then we get R (0220), for V check both
    NSString * hs = [NSString hexStringWithData:sig ofLength:siglen];
    
    NSString * sec =[NSString hexStringWithData:key ofLength:32];
    
    NSLog(@"secret: %@---", [NSString hexStringWithData:key ofLength:32] );
    NSLog(@"message hash:%@---", [NSString hexStringWithData:hashedTransaction ofLength:32]);
    NSLog(@"signature:%@---",[NSString hexStringWithData:signature.data ofLength:64]);
    NSLog(@"DER signature:%@---", hs);
    
    //TODO:https://blog.engelke.com/2014/10/17/parsing-ber-and-der-encoded-asn-1-objects/
    
    
    
    
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
    
//  Tested in testrpc, take the pk, drop the first byte as that is just a compression flag, run it through keccak_256, drop the first 24 chars, that is your ethereum public address!  web3.sha3("0x9d2727b8e69f0e77fbe15143b163661be815d1ca731be335d53388731a765e7dc55e015815d199104bf9ebe8b59917ac6f573035c0b895006e4aa455f7d9fa97",{encoding:'hex'})
    NSString * pk =[NSString hexStringWithData:output ofLength:65];
    
    //https://ethereum.stackexchange.com/questions/3542/how-are-ethereum-addresses-generated
    //    Start with the public key (128 characters / 64 bytes)
    //    Take the Keccak-256 hash of the public key. You should now have a string that is 64 characters / 32 bytes. (note: SHA3-256 eventually became the standard, but Ethereum uses Keccak)
    //    Take the last 40 characters / 20 bytes of this public key (Keccak-256). Or, in other words, drop the first 24 characters / 12 bytes. These 40 characters / 20 bytes are the address. When prefixed with 0x it becomes 42 characters long.
    //TODO: everything has to be passed as hex data, not string, so convert hex string to NSData -> unsigned char
    //https://stackoverflow.com/questions/3056757/how-to-convert-an-nsstring-to-hex-values
    
    uint8_t EthereumAddress[32];
    uint8_t ss[64];
    memcpy(ss, output+1,64);
    keccack_256(EthereumAddress, 32,ss, 64);
    //THIS IS CORRECT when referenced against:
    //web3.sha3("0x"+ss_val,{encoding:"hex"})
    NSLog(@"Ethereum address (remove first 24 characters):%@",[[NSString hexStringWithData:EthereumAddress ofLength:32] substringFromIndex:24]);
    
    
    NSLog(@"return value of pub key = %d, key:%@, compressed_pk:%@, pk:%@", v,sec, compressed_pk,pk);
    
    v= secp256k1_ecdsa_verify(ctx, &signature, hashResult, &pubkey);
    NSLog(@"return value of signature verification = %d", v);

    NSLog(@"sig from der:%@",[NSString hexStringWithData:signatureFromDer.data ofLength:64]);
    
    v= secp256k1_ecdsa_verify(ctx, &signatureFromDer, hashResult, &pubkey);
    NSLog(@"return value of signature from DER verification = %d", v);

    //secp256k1_ecdsa_signature_serialize_der(ctx, signature, &siglen, &signature)

    // Do any additional setup after loading the view, typically from a nib.
    secp256k1_context_destroy(ctx);
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


/*
 web3.js
 "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8",28,"0x7f003cee8d3c57cdff4b2bbd9f7a34dd94fc68add88555d8075179c63eec7c83", "0x5fd738477efde6e8b1282192af57c0809f43a36eb5d05d4655e840b56f349f67"
 
 
 //NO PREFIX + NO INVERTED S and R! TEST#1
  "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8",27,  "0xb21782a48dc5f210481c431139b78a1859702756e91fdb28b01ac487d8b98c89","0x2fb7b34354a3018d0e326d4d69e72957335d3032334b148de83bd3efef25fa2c"
 
 Ethereum address (remove first 24 characters):31031df1d95a84fc21e80922ccdf83971f3e755b
 
 VERIFIED WITH SOLIDITY: 
 function verify3(bytes32 _message, uint8 _v, bytes32 _r, bytes32 _s) constant returns (address) {
 bytes memory prefix = "\x19Ethereum Signed Message:\n32";
 bytes32 prefixedHash = sha3(prefix, _message);
 address signer = ecrecover(_message, _v, _r, _s);
 return signer;
 }
 
 TEST#2 - VALID
 3045022100
 0220
 "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8",
 27,
 "0xeb898f6a128993dfa0d0f624238047d9e3baf68301e724d64307b8a805db4f45",
 "0x6a24d8942c8faefb6be98b09c524664d1d2012e574b263113e50437a7a7fdb9e",
 
 
 TEST#3 TEST VALID for DER 3044 protocol
 
 secret: 8595f846b34acad9923b86e914a7bb991d44d6b7a9556d0aff5e3c7edb015261---
 message hash:1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8---
 signature:3447643c820391a5d49c4a3a70a1d120202ea0539c13c97bcdd8629c3aed2f70cc714c26a91b285f2c5ca70605397c08f0150478d7a69782c769f992e0023f0f---
 
 DER signature:30440220702fed3a9c62d8cd7bc9139c53a02e2020d1a1703a4a9cd4a59103823c64473402200f3f02e092f969c78297a6d7780415f0087c390506a75c2c5f281ba9264c71cc---
 
 Ethereum address (remove first 24 characters):2e5745ba28b327c6ad5178580d1b8a8fad330db3
 
 return value of pub key = 1, key:8595f846b34acad9923b86e914a7bb991d44d6b7a9556d0aff5e3c7edb015261, compressed_pk:020d67d45aaf773c9fd12a505df33bc986d2fd0dcb00da42b48c994bdbda4eb5a9, pk:040d67d45aaf773c9fd12a505df33bc986d2fd0dcb00da42b48c994bdbda4eb5a99ce338d1414861c44c7c616865eb7ff274f3ae92c3e0c1b048f2f992a65c06c6
 
 Solidity Params:

 "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8",  27,  "0x5f0dbf89ece9f2f6c7e8923f6f9f3f68c4e651a452f575ce27565d26804fc8f2" ,
     "0x1a3a8fddd22367bd1e77b777499dfd625049c2aa7345ad36fb3764150d7d34f9"
 
 
 
 3045
 022100
 "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8",  27,  "0xe7ff81822519aac101acbc44af69b2772315a291f1970096e3406b9355d14b4e",
     "0x053fa6f38dcc4084a0cb5b9cd4957c6b5188abc3021d069cae17ab1edd7e773c"
 */

//DER signature parser from https://github.com/bitcoin-core/secp256k1/blob/0b7024185045a49a1a6a4c5615bf31c94f63d9c4/src/ecdsa_impl.h

static int der_sig_parse(char *rr, char *rs, const unsigned char *sig, size_t size) {
    const unsigned char *sigend = sig + size;
    int rlen;
    if (sig == sigend || *(sig++) != 0x30) {
        /* The encoding doesn't start with a constructed sequence (X.690-0207 8.9.1). */
        return 0;
    }
    rlen = secp256k1_der_read_len(&sig, sigend);
    if (rlen < 0 || sig + rlen > sigend) {
        /* Tuple exceeds bounds */
        return 0;
    }
    if (sig + rlen != sigend) {
        /* Garbage after tuple. */
        return 0;
    }
    
    if (!secp256k1_der_parse_integer(rr, &sig, sigend)) {
        return 0;
    }
    if (!secp256k1_der_parse_integer(rs, &sig, sigend)) {
        return 0;
    }
    
    if (sig != sigend) {
        /* Trailing garbage inside tuple. */
        return 0;
    }
    
    return 1;
}

static int secp256k1_der_parse_integer(char *r, const unsigned char **sig, const unsigned char *sigend) {
    int overflow = 0;
    unsigned char ra[32] = {0};
    int rlen;
    
    if (*sig == sigend || **sig != 0x02) {
        /* Not a primitive integer (X.690-0207 8.3.1). */
        return 0;
    }
    (*sig)++;
    rlen = secp256k1_der_read_len(sig, sigend);
    if (rlen <= 0 || (*sig) + rlen > sigend) {
        /* Exceeds bounds or not at least length 1 (X.690-0207 8.3.1).  */
        return 0;
    }
    if (**sig == 0x00 && rlen > 1 && (((*sig)[1]) & 0x80) == 0x00) {
        /* Excessive 0x00 padding. */
        return 0;
    }
    if (**sig == 0xFF && rlen > 1 && (((*sig)[1]) & 0x80) == 0x80) {
        /* Excessive 0xFF padding. */
        return 0;
    }
    if ((**sig & 0x80) == 0x80) {
        /* Negative. */
        overflow = 1;
    }
    while (rlen > 0 && **sig == 0) {
        /* Skip leading zero bytes */
        rlen--;
        (*sig)++;
    }
    if (rlen > 32) {
        overflow = 1;
    }
    if (!overflow) {
        memcpy(ra + 32 - rlen, *sig, rlen);
        
        //secp256k1_scalar_set_b32(r, ra, &overflow);
    }
    if (overflow) {
        //secp256k1_scalar_set_int(r, 0);
    }
    (*sig) += rlen;
    
    memcpy(r,ra,rlen);
    return 1;
}

static int secp256k1_der_read_len(const unsigned char **sigp, const unsigned char *sigend) {
    int lenleft, b1;
    size_t ret = 0;
    if (*sigp >= sigend) {
        return -1;
    }
    b1 = *((*sigp)++);
    if (b1 == 0xFF) {
        /* X.690-0207 8.1.3.5.c the value 0xFF shall not be used. */
        return -1;
    }
    if ((b1 & 0x80) == 0) {
        /* X.690-0207 8.1.3.4 short form length octets */
        return b1;
    }
    if (b1 == 0x80) {
        /* Indefinite length is not allowed in DER. */
        return -1;
    }
    /* X.690-207 8.1.3.5 long form length octets */
    lenleft = b1 & 0x7F;
    if (lenleft > sigend - *sigp) {
        return -1;
    }
    if (**sigp == 0) {
        /* Not the shortest possible length encoding. */
        return -1;
    }
    if ((size_t)lenleft > sizeof(size_t)) {
        /* The resulting length would exceed the range of a size_t, so
         * certainly longer than the passed array size.
         */
        return -1;
    }
    while (lenleft > 0) {
        ret = (ret << 8) | **sigp;
        if (ret + lenleft > (size_t)(sigend - *sigp)) {
            /* Result exceeds the length of the passed array. */
            return -1;
        }
        (*sigp)++;
        lenleft--;
    }
    if (ret < 128) {
        /* Not the shortest possible length encoding. */
        return -1;
    }
    return ret;
}

@end
