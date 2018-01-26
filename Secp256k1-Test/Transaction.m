//
//  Transaction.m
//  Secp256k1-Test
//
//  Created by Amit Shah on 2018-01-03.
//  Copyright © 2018 Amit Shah. All rights reserved.
//

#import "Transaction.h"
#import "RLPSerialization.h"


static NSData *NullData = nil;

@implementation Transaction{
    char *r;
    char *s;
    uint8_t v;
}


+ (void) testBigNumber{
    mp_int number1, number2, number3;
    
   
    mp_init(&number2);
    mp_init(&number3);
    
    mp_read_radix(&number1, "0a120edfff558c98a73015d5d67e8990", 16);
    mp_read_radix(&number2, "12e6f45d698c7b7009a841c1348d6ff4", 16);
    
    mp_mul(&number1, &number2, &number3);
    
    char output[1000];
    mp_toradix(&number3, output, 16);
    NSLog(@"number3:%s", output);
    
    mp_div(&number3, &number1, &number2, NULL);
    mp_toradix(&number2, output, 16);
    NSLog(@"number2:%s", output);
}



- (NSMutableArray*)_packBasic {
    //based on specification, all these are tightly packed i.e. no 0 padding
    NSMutableArray *result = [NSMutableArray arrayWithCapacity:9];
    
    {
        
        NSData *nonceData = stripDataZeros(convertMPInt(self.nonce));
        if (nonceData.length > 32) { return nil; }
        [result addObject:nonceData];
    }
    
    if (!mp_iszero(&(_gasPrice)) ) {
        
        NSData *gasPriceData = stripDataZeros(convertMPInt(_gasPrice));
        if (gasPriceData.length > 32) { return nil; }
        [result addObject:gasPriceData];
    } else {
        [result addObject:[NSNull null]];
    }
    
    if (!mp_iszero(&_gasLimit)) {
        NSData *gasLimitData = stripDataZeros(convertMPInt(_gasLimit));
        if (gasLimitData.length > 32) { return nil; }
        [result addObject:gasLimitData];
    } else {
        [result addObject:[NSNull null]];
    }
    
    if (self.toAddress) {
        [result addObject:[NSData dataWithBytes:self.toAddress length:20]];
    } else {
        [result addObject:[NSNull null]];
    }
    
    if (!mp_iszero(&_value)) {
        NSData *valueData = stripDataZeros(convertMPInt(_value));
        if (valueData.length > 32) { return nil; }
        [result addObject:valueData];
    } else {
        [result addObject:[NSNull null]];
    }
    
    if (self.data) {
        //TODO
        //[result addObject:[NSData dataWithBytes:self.data length:20]];
        [result addObject:self.data];
    } else {
        [result addObject:[NSNull null]];
    }
    
    return result;
}

- (NSData*)signSerialize {
    NSMutableArray *raw = [self _packBasic];
    return [RLPSerialization dataWithObject:raw error:nil];
}

-(void) setS:(char*) _s{
    if(!s){
        s = malloc(sizeof(char)*32);
    }
    memcpy(s, _s, 32);

}

-(void) setR:(char*) _r{
    if(!r){
        r = malloc(sizeof(char) * 32);
    }
    memcpy(r,_r,32);
}

-(void)  getR:(char*) _r{
    memcpy(_r,r,32);
}

-(void)  getS:(char*) _s{
    memcpy(_s,s,32);
}

-(void) setV:(uint8_t) _v{
    v = _v;
}

-(uint8_t) getV{
    return v;
}
-(void)dealloc {
    if(s){
        free(s);}
    if(r){
        free(r);}
}
- (NSData*)serialize: (bool) _signature {
    NSMutableArray *raw = [self _packBasic];
    
    if (_signature) {
        //uint8_t v = 28;
        //TODO: you cant just default to 28, you need to determine based on sig recovery if its 1 or 0 + 27
        //TODO we need to use the proper chainId
        //if (_chainId) { v += _chainId * 2 + 8; }
        //NSLog(@"CHAIN ID:%d", v);
        ;
        //http://localhost:8080/dist/ethereumjs-vm/node_modules/ethereumjs-tx/node_modules/ethereumjs-util/index.js
        //line 333
        [raw addObject:dataWithByte(v + 27)];
        [raw addObject:stripDataZeros([NSData dataWithBytes:r length:32])];
        [raw addObject:stripDataZeros([NSData dataWithBytes:s length:32])];
        //[raw addObject:stripDataZeros(self.signature.s)];
        
    } else
    {
        NSLog(@"CHAIN ID:%d", _chainId);

        //EIP115
        //This identifies which network this singed transaction is valid for.  27 is any so
        //MAD DANGER
        [raw addObject:dataWithByte(_chainId ? _chainId: 28)];
        [raw addObject:[NSNull null]];
        [raw addObject:[NSNull null]];
    }
    
    return [RLPSerialization dataWithObject:raw error:nil];
}
@end
