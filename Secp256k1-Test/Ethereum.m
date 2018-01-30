//
//  Ethereum.m
//  Secp256k1-Test
//
//  Created by Amit Shah on 2018-01-25.
//  Copyright © 2018 Amit Shah. All rights reserved.
//



#import "Ethereum.h"
#import "RLPSerialization.h";

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
}


@end


//uncomment to test random key generation with kSecRandom
//#define RANDOM_KEY

//uncomment to test creating contract
//#define CREATE_CONTRACT

static int custom_nonce_function_rfc6979(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter){
    return secp256k1_nonce_function_rfc6979(nonce32, msg32, key32, algo16, data, counter);
}


@implementation Ethereum{

    secp256k1_context * ctx;
    //TODO we should use secure memory for this
    unsigned char key[32];
    secp256k1_pubkey pubkey;
    uint8_t EthereumAddress[32];
}

//https://ethereum.stackexchange.com/questions/29139/how-does-solidity-tightly-packed-arguments-work-in-sha256
//address :  [NSString dataFromHex:@"address"]
//boolean : [NSData appendByte:&value length:1]
//
+(NSData*) packSolidity:(NSArray*) params withArgs: (NSArray*) objects{
    NSMutableData * result = [NSMutableData alloc];
    int i = 0;
    for(NSString* param in params){
        
        if([param hasPrefix:@"bytes"]){
            [result appendData:objects[i]];
        }else if([param isEqualToString:@"address"]){
            [result appendData:[(NSString*)objects[i] dataFromHexString]];
        }else if([param isEqualToString:@"string"]){
            [result appendData:[NSData dataWithBytes:[(NSString*)objects[i] UTF8String ] length:[(NSString*)objects[i] length]]];
        }else if([param isEqualToString:@"bool"]){
            //TODO unhandled, user should pass in uint8 value
        }else if([param hasPrefix:@"uint"]){
            [result appendData:stripDataZeros([(NSNumber*)objects[i] getData])];
        }
        i++;
    }
    return result;

}







-(id) init{
    id obj = [super init];
    if(!ctx){
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }
   
    memcpy(key,[@"e331b6d69882b4cb4ea581d88e0b604039a3de5967688d3dcffdd2270c0fd109" dataFromHexString].bytes,
           32);
    size_t output_size = 65;
    unsigned char output[65];
    
    //get your public key
    int v = secp256k1_ec_pubkey_create(ctx, &pubkey, key);
    
    
    secp256k1_ec_pubkey_serialize(ctx,
                                  output,
                                  &output_size,
                                  &pubkey,
                                  SECP256K1_EC_UNCOMPRESSED
                                  );
    
    //https://bitcoin.stackexchange.com/questions/3059/what-is-a-compressed-bitcoin-key
    //https://brainwalletx.github.io/#generator to validate sec == public key
    
    //  Tested in testrpc, take the pk, drop the first byte as that is just a compression flag, run it through keccak_256, drop the first 24 chars, that is your ethereum public address!  web3.sha3("0x9d2727b8e69f0e77fbe15143b163661be815d1ca731be335d53388731a765e7dc55e015815d199104bf9ebe8b59917ac6f573035c0b895006e4aa455f7d9fa97",{encoding:'hex'})
    
    //https://ethereum.stackexchange.com/questions/3542/how-are-ethereum-addresses-generated
    //    Start with the public key (128 characters / 64 bytes)
    //    Take the Keccak-256 hash of the public key. You should now have a string that is 64 characters / 32 bytes. (note: SHA3-256 eventually became the standard, but Ethereum uses Keccak)
    //    Take the last 40 characters / 20 bytes of this public key (Keccak-256). Or, in other words, drop the first 24 characters / 12 bytes. These 40 characters / 20 bytes are the address. When prefixed with 0x it becomes 42 characters long.
    //TODO: everything has to be passed as hex data, not string, so convert hex string to NSData -> unsigned char
    //https://stackoverflow.com/questions/3056757/how-to-convert-an-nsstring-to-hex-values
    
    uint8_t ss[64];
    memcpy(ss, output+1,64);
    keccack_256(EthereumAddress, 32,ss, 64);
    NSLog(@"Ethereum address (remove first 24 characters):%@",[[NSString hexStringWithData:EthereumAddress ofLength:32] substringFromIndex:24]);
    
    return obj;
    
}

-(void) signMessage:(NSString *) msg{
}
-(void) signDigest:(char*) hash{
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
- (void)testCall:(NSString*) hexContractAddress {
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

    NSData * transactionEncoding = [t signSerialize];
    //const char *bytes = [d bytes];
    
    NSLog(@"%@",[NSString hexStringWithData:transactionEncoding.bytes ofLength:transactionEncoding.length]);
    
    uint8_t hashedTransaction[32];
    
    //NOTE: for signing we set chainId = 0, we only need the first 6 params (no r,s,v) -> keccak hash -> sign
    //Therefore, it is not safe to use [Transaction serliaze:false] fos signing purpose! You must use signSerialize
    keccack_256(hashedTransaction, 32, (uint8_t*)transactionEncoding.bytes , transactionEncoding.length);

    Contract * c = [Contract alloc];
    NSData* mhash = [c getMethodHash:@"verify(bytes32,uint8,bytes32,bytes32)"];
    NSArray * verifyParams = @[@"bytes32", @"uint8", @"bytes32", @"bytes32"];
    char tempR[32];
    char tempS[32];
    [t getR:tempR];
    [t getS:tempS];
    
    NSArray * verifyArgs = @[[NSString hexStringWithData:hashedTransaction ofLength:32], [NSNumber numberWithLong:28],
                             [NSString hexStringWithData: tempR ofLength:32] ,[NSString hexStringWithData:tempS ofLength:32] ];
    NSData * verifyData = [c rawEncode:verifyParams withVals:verifyArgs];
    NSLog(@"web3.eth.call({to:'0x%@', data:'%@%@'})",
    hexContractAddress,
    [NSString hexStringWithData:mhash.bytes ofLength:mhash.length],
    [NSString hexStringWithData:verifyData.bytes ofLength:verifyData.length]);

}

-(void) testContractCreation{
    mp_int gasLimit;
    mp_init(&gasLimit);
    mp_set(&gasLimit, 410000);
    
    mp_int gasPrice;
    mp_init(&gasPrice);
    mp_set(&gasPrice, 4700);
    
    mp_int nonce;
    mp_init(&nonce);
    mp_set(&nonce, 1);
    
    mp_int value;
    mp_init(&value);
    mp_set(&value, 0);
    
    
   
    //t.toAddress = address;
    NSString *filepath = [[NSBundle mainBundle] pathForResource:@"Verify_sol_Verify" ofType:@"bin"];
    NSError *error;
    NSData* contractData = [[NSString stringWithContentsOfFile:filepath encoding:NSUTF8StringEncoding error:&error]
                            dataFromHexString];
    
    Transaction* t = [self createTransaction:nonce withGasLimit:gasLimit withGasPrice:gasPrice withValue:value withToAddress:nil withData:contractData];
    
    [self signAndSetSignatureFor:t];
    NSData * tx = [t serialize:true];
    
    NSLog(@"web3.eth.sendRawTransaction('%@')",[NSString hexStringWithData:tx.bytes ofLength:tx.length]);
    

}

-(void) testMerkleProof{
        NSMutableArray * merkleElements = [NSMutableArray arrayWithCapacity:100];
        MerkleTree * mt = [[MerkleTree alloc] init:merkleElements];
        for(int i=0; i < 10; i++){
            char meh[32];
            char* elem = [[NSString stringWithFormat:@"elem%d",i] UTF8String];
            keccack_256(meh, 32, elem, 5);
            NSValue * v =[NSValue value:meh withObjCType:@encode(char[32])];
            //[merkleElements addObject:v];
            [mt appendElement:v];
        }
        [mt generateHashTree];
    
        [mt printMerkleTree];
        char proofElement[32];
        [merkleElements[9] getValue:proofElement];
        NSArray* proof = [mt generateProof:[NSData dataWithBytes:proofElement length:32] withRoot:NULL];
    
        NSLog(@"\r -----------------generated proof---------------- \r");
        for(NSValue * v in proof){
            char p[32];
            [v getValue:p];
            NSLog(@"proof: %@--\r", [NSString hexStringWithData:p ofLength:32]);
        }
    

}
- (void)testTransaction {
    
    
    mp_int gasLimit;
    mp_init(&gasLimit);
    mp_set(&gasLimit, 210000);
    
    mp_int gasPrice;
    mp_init(&gasPrice);
    mp_set(&gasPrice, 4700);
    
    mp_int nonce;
    mp_init(&nonce);
    mp_set(&nonce, 1);
    
    mp_int value;
    mp_init(&value);
    mp_set(&value, 3200);
    
    
    Transaction* t = [self createTransaction:nonce withGasLimit:gasLimit withGasPrice:gasPrice withValue:value withToAddress:@"1f36f546477cda21bf2296c50976f2740247906f" withData:[NSNull null]];
    
    [self signAndSetSignatureFor:t];
    NSData * tx = [t serialize:true];
    
    NSData * txReceipt = [t serialize:false];
    
    char txHash[32];
    keccack_256(txHash, 32, txReceipt.bytes, txReceipt.length);
    
    NSLog(@"web3.eth.sendRawTransaction('0x%@')",[NSString hexStringWithData:tx.bytes ofLength:tx.length]);
    NSLog(@"web3.eth.getTransactionReceipt('0x%@')",[NSString hexStringWithData:txHash ofLength:32]);
}
-(void)dealloc {
    secp256k1_context_destroy(ctx);
}

-(void) testPackSolidity{

    NSData * msg = [Ethereum packSolidity:@[@"address",@"uint256"] withArgs:@[@"ca35b7d915458ef540ade6068dfe2f44e8fa733c",[NSNumber numberWithInteger:123]]];
    char hash[32];
    
    keccack_256(&hash, 32, msg.bytes, msg.length);
    
    if([[NSString hexStringWithData:hash ofLength:32] isEqualToString:  @"b6ebad627fe36c006201d0e5e23434c71d2c8c56d24ba787c50a09b814c42db8"]){
        NSLog(@"pass solidity tightly packed hashing test");
    }
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
