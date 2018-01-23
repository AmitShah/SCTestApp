//
//  MerkleTree.m
//  Secp256k1-Test
//
//  Created by Amit Shah on 2018-01-22.
//  Copyright © 2018 Amit Shah. All rights reserved.
//

#import "MerkleTree.h"
#import <keccak-tiny.h>


@implementation MerkleTree

-(nonnull id) init: (NSArray*) _leafNodes{
    self = [super init];
    
    self.levels = [NSMutableArray arrayWithCapacity:log2([_leafNodes count])];
    [self.levels addObject:_leafNodes];
    [self generateHashTree];
    return self;
}


-(void) generateHashTree{
    NSArray * level = [NSArray arrayWithArray:self.levels[0]];
    NSMutableArray *result = [NSMutableArray arrayWithCapacity: log2([self.leafNodes count])];
    do{
        //212afc935a5685e12f22195713fac5ba98989c7dda8b0764f5e8256fc1544a075b9972cfef311465c48e55f03a979b661529a5671b939fdd85e842af34650d90
        level = [self sumLevel: level];
        [self.levels addObject:level];
        
    }while([level count]> 1);
}

//NSArray of NSValues encoding keccak256 hashes of the transactions in order of nonce
-(NSArray *) sumLevel:(NSArray*) elements{
    //move to front of array
    NSMutableArray * temp = [NSMutableArray arrayWithArray:elements];
    NSMutableArray * result = [NSMutableArray arrayWithCapacity:[elements count]/2] ;
    
    uint8_t buffer[64];
    
    uint8_t hash[32];
    uint8_t * zero =  (uint8_t*)[[NSMutableData dataWithLength:32] bytes];
    int k = 0;
    
//    we cant really balance the tree, that maybe crazy at larger transaction counts
//      akin to perhaps preallocating a binary tree
    
//    if([temp count] % 2 != 0){
//        
//        
//         
//        keccack_256(hash, 32, zero, 32);
//        [temp addObject:[NSValue valueWithPointer:hash]];
//    }
   
    while(k < [elements count]){
        
        uint8_t a[32];
        uint8_t b[32];
        
        [(NSValue *)elements[k++] getValue:a];
        if(k < [elements count]){
            
            [(NSValue *)elements[k++] getValue:b];
            memcpy(buffer, a, 32);
            //https://stackoverflow.com/questions/1163624/memcpy-with-startindex
            memcpy(buffer+32, b, 32);
        
        //we re-use and blowup the hash value stored
            keccack_256(hash, 32, buffer, 64);
            [result addObject:[NSValue value:hash withObjCType:@encode(char[32])]];
        
        }else{
            //send up the hash as is on the tree
            [result addObject:elements[k-1]];
        }
    }
    
    
    //move enumerator back to the end
    
    return result;
}


-(void) printMerkleTree{
    int k =0;
    
    for(NSArray * level in self.levels){
        NSLog(@"----------------LEVEL %d--------- \r\n \r\n", k);
        for(NSValue * v in level){
            char h[32];
            [v getValue:h];
            NSLog(@"%@", [NSData dataWithBytes:h length:32]);
        }
        k++;
    }
}
@end
