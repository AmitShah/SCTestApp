//
//  Ethereum.m
//  Secp256k1-Test
//
//  Created by Amit Shah on 2018-01-25.
//  Copyright © 2018 Amit Shah. All rights reserved.
//



#import "Ethereum.h"


@implementation NSData (NSData_hexadecimalString)

- (NSString *)hexString {
    const unsigned char *dataBuffer = (const unsigned char *)[self bytes];
    if (!dataBuffer) return [NSString string];
    
    NSUInteger          dataLength  = [self length];
    NSMutableString     *hexString  = [NSMutableString stringWithCapacity:(dataLength * 2)];
    
    for (int i = 0; i < dataLength; ++i)
        [hexString appendString:[NSString stringWithFormat:@"%02lx", (unsigned long)dataBuffer[i]]];
    
    return [NSString stringWithString:hexString];
}

@end

@implementation NSString (Hex)

+ (NSString*) hexStringWithData: (unsigned char*) data ofLength: (NSUInteger) len
{
    NSMutableString *tmp = [NSMutableString string];
    for (NSUInteger i=0; i<len; i++)
        [tmp appendFormat:@"%02x", data[i]];
    return [NSString stringWithString:tmp];
}

- (NSData *)dataFromHexString {
    return dataFromChar([self UTF8String],(int)[self length]  );
    //    const char *chars = [self UTF8String];
    //    int i = 0, len = self.length;
    //
    //    NSMutableData *data = [NSMutableData dataWithCapacity:len / 2];
    //    char byteChars[3] = {'\0','\0','\0'};
    //    unsigned long wholeByte;
    //
    //    while (i < len) {
    //        byteChars[0] = chars[i++];
    //        byteChars[1] = chars[i++];
    //        wholeByte = strtoul(byteChars, NULL, 16);
    //        [data appendBytes:&wholeByte length:1];
    //    }
    //    //unsigned char *bytePtr = (unsigned char *)[data bytes];
    //    return data;
}


@end


//uncomment to test random key generation with kSecRandom
//#define RANDOM_KEY

//uncomment to test creating contract
//#define CREATE_CONTRACT

//TODO, we want to wrap this to change our nonce on demand
static int custom_nonce_function_rfc6979(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter){
    
    return secp256k1_nonce_function_rfc6979(nonce32, msg32, key32, algo16, data, counter);
}


@implementation Ethereum

secp256k1_context * ctx;
unsigned char key[32];

-(id) init{
    id obj = [super init];
    if(!ctx){
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }
   
    memcpy(key,[@"e331b6d69882b4cb4ea581d88e0b604039a3de5967688d3dcffdd2270c0fd109" dataFromHexString].bytes,
           32);
    return obj;
    
}

//returns the data parameter, this can be executed directly with eth_call or loaded into a transactions data params
-(NSData*) encodeMethodForCall:(NSString *) method withParams:(NSArray*) params withArgs:(NSArray*) args{
    Contract *c = [[Contract alloc] init];
    NSMutableData * val = [NSMutableData dataWithData:[c getMethodHash:method]];
    [val appendData:[c rawEncode:params withVals:args]];
    return val;
}

//https://ethereum.stackexchange.com/questions/760/how-is-the-address-of-an-ethereum-contract-computed
-(NSString*) getContractAddress:(NSString *) _hexEncodedSenderAddress withNonce:(NSValue *) _nonce{
    //Deterministically calculating a Contracts Address Test
    NSData *senderAddress = dataFromChar([_hexEncodedSenderAddress UTF8String], 40);
    mp_int nonce;
    [_nonce getValue:&nonce];
    NSData * nonceData = convertMPInt(nonce);
    NSMutableArray * raw = [NSMutableArray arrayWithObjects:senderAddress,nonceData,nil];
    NSData* rlpRaw = [RLPSerialization dataWithObject:raw error:nil];
    uint8_t hashedContractAddress[32];
        keccack_256(hashedContractAddress, 32, (uint8_t*)rlpRaw.bytes , rlpRaw.length);
    NSString* contractAddress = [[NSString hexStringWithData:hashedContractAddress ofLength:32 ] substringFromIndex:24];
    return contractAddress;
}


-(Transaction *) createTransaction:(mp_int ) nonce withGasLimit: (mp_int) gasLimit withGasPrice:(mp_int) gasPrice withValue:(mp_int) value withToAddress:(NSString *) toAddress withData: (NSData*) data{
    Transaction* t = [[Transaction alloc] init];
    t.gasLimit = gasLimit;
    t.gasPrice = gasPrice;
    t.nonce = nonce;
    uint8_t * address = (uint8_t*)[toAddress dataFromHexString].bytes;
    t.toAddress = address;
    t.data = data;
    t.value = value;
    return t;
}

-(NSData *) _signableHash:(Transaction*)t{
    NSData * serialized = [t signSerialize];
    char hash[32];
    keccack_256(hash, 32, (uint8_t*)(serialized.bytes), serialized.length);
    return dataFromChar(hash, 32);
}

//after this you can call [t serialize] for a transaction. This is not neccessary for a call, you merely need to RLP encode for a call
-(void) signAndSetSignatureFor: (Transaction*)t{
    NSData * serialized = [t signSerialize];
    NSLog(@"serialized tx: %@", [NSString hexStringWithData:serialized.bytes ofLength:serialized.length]);
    char hashedTransaction[32];
    keccack_256(hashedTransaction, 32, (uint8_t*)(serialized.bytes), serialized.length);
    NSLog(@"hashed tx: %@", [NSString hexStringWithData:hashedTransaction ofLength:32]);
    secp256k1_ecdsa_signature signature;
    unsigned char sig[74];
    size_t siglen = 74;
    secp256k1_ecdsa_recoverable_signature recoverable_sig;
    
    secp256k1_ecdsa_sign_recoverable(ctx, &recoverable_sig, hashedTransaction, key, custom_nonce_function_rfc6979, NULL);
    
   
    secp256k1_ecdsa_recoverable_signature_convert(ctx,
                                                  &signature,
                                                  &recoverable_sig);
    
    //secp256k1_ecdsa_signature_recoverable_serialize_der(ctx, sig, &siglen, &signature);
    //secp256k1_ecdsa_sign(ctx, &signature, hashedTransaction, key, custom_nonce_function_rfc6979, NULL);
    secp256k1_ecdsa_signature_serialize_der(ctx, sig, &siglen, &signature);
    uint8_t r[32];
    uint8_t s[32];
    der_sig_parse(r,s, sig, siglen);
    //t.s = s;
    //t.r = r;
    
    [t setS:&s[0]];
    [t setR:&r[0]];
    [t setV:(uint8_t)recoverable_sig.data[64]];
    //NSLog(@"SIG R: %@---", [NSString hexStringWithData:[t getR] ofLength:32 ] );
    //NSLog(@"SIG S: %@---", [NSString hexStringWithData:[t getS] ofLength:32 ]);
    
}

- (void)testTransaction {
    
//   
//    
//    NSMutableArray * merkleElements = [NSMutableArray arrayWithCapacity:100];
//    for(int i=0; i < 10; i++){
//        char meh[32];
//        char* elem = [[NSString stringWithFormat:@"elem%d",i] UTF8String];
//        keccack_256(meh, 32, elem, 5);
//        NSValue * v =[NSValue value:meh withObjCType:@encode(char[32])];
//        [merkleElements addObject:v];
//    }
//    
//    MerkleTree * mt = [[MerkleTree alloc] init:merkleElements];
//    [mt printMerkleTree];
//    char proofElement[32];
//    [merkleElements[9] getValue:proofElement];
//    NSArray* proof = [mt generateProof:[NSData dataWithBytes:proofElement length:32] withRoot:NULL];
//    
//    NSLog(@"\r -----------------generated proof---------------- \r");
//    for(NSValue * v in proof){
//        char p[32];
//        [v getValue:p];
//        NSLog(@"proof: %@--\r", [NSString hexStringWithData:p ofLength:32]);
//    }
    
    
    mp_int gasLimit;
    mp_init(&gasLimit);
    mp_set(&gasLimit, 210000);
    
    mp_int gasPrice;
    mp_init(&gasPrice);
    mp_set(&gasPrice, 4700);
    
    mp_int nonce;
    mp_init(&nonce);
    mp_set(&nonce, 2);
    
    mp_int value;
    mp_init(&value);
    mp_set(&value, 3200);
    
    
    Transaction* t = [self createTransaction:nonce withGasLimit:gasLimit withGasPrice:gasPrice withValue:value withToAddress:@"1f36f546477cda21bf2296c50976f2740247906f" withData:[NSNull null]];
    
    [self signAndSetSignatureFor:t];
    NSData * tx = [t serialize:true];
    
    
    
    NSLog(@"web3.eth.sendRawTransaction('%@')",[NSString hexStringWithData:tx.bytes ofLength:tx.length]);
        //TEST calling verify method on contract
    
//    NSLog(@"\r TEST web3.eth.call verify signature, return value in geth should equal 0x000000000000000000000000be862ad9abfe6f22bcb087716c7d89a26051f74c\r");
//    
//    NSData* mhash = [c getMethodHash:@"verify(bytes32,uint8,bytes32,bytes32)"];
//    NSArray * verifyParams = @[@"bytes32", @"uint8", @"bytes32", @"bytes32"];
//    NSArray * verifyArgs = @[[NSString hexStringWithData:hashedTransaction ofLength:32], [NSNumber numberWithLong:28],
//                             [NSString hexStringWithData:t.r ofLength:32] ,[NSString hexStringWithData:t.s ofLength:32] ];
//    NSData * verifyData = [c rawEncode:verifyParams withVals:verifyArgs];
//    NSLog(@"web3.eth.call({to:'<CONTRACT_ADDRESS>', data:'%@%@'})",
//          [NSString hexStringWithData:mhash.bytes ofLength:mhash.length],
//          [NSString hexStringWithData:verifyData.bytes ofLength:verifyData.length]);
//    
//    NSLog(@"\r\r");
}
-(void)dealloc {
    secp256k1_context_destroy(ctx);
}




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
