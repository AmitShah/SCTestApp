//
//  NSNumber+BigNumber.m
//  Secp256k1-Test
//
//  Created by Amit Shah on 2018-01-14.
//  Copyright © 2018 Amit Shah. All rights reserved.
//

#import "NSNumber+BigNumber.h"
#import "Transaction.h"



@implementation NSNumber (BigNumber)
// Subclass
 mp_int * _bigInt;

-(void)setBigIntValue:(long) value{
    if(!_bigInt){
        _bigInt = malloc(sizeof(mp_int));
        mp_init_set_int(_bigInt, value);
    }else{
        mp_set_int(_bigInt, value);
    }
}

//TODO fix this function, we should be creating a BigInt class :(

- (NSData *) getData {
    mp_int b;
    mp_init(&b);
    mp_set_long_long(&b,[self longLongValue]);
    return convertMPInt(b);//    char * hex;
//    int size;
//    mp_int t;
//    mp_init(&t);
//    
//    mp_copy(_bigInt, &t);
//    mp_radix_size(&t, 16, &size);
//    mp_toradix(&t, hex, 16);
//    return dataFromChar(hex, size);
}

@end
