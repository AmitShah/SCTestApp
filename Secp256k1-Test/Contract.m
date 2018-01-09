//
//  Contract+Contract.m
//  Secp256k1-Test
//
//  Created by Amit Shah on 2018-01-04.
//  Copyright © 2018 Amit Shah. All rights reserved.
//

#import "Contract.h"

@implementation Contract

-(id) init: (NSString*)abi{
    
    self = [super init];
    NSMutableArray *result = [NSJSONSerialization JSONObjectWithData:[abi dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingMutableContainers error:nil];
    NSLog(@"Result = %@",result);
    
    for (NSMutableDictionary *dic in result)
    {
        NSString *string = dic[@"array"];
        if (string)
        {
            NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
            dic[@"array"] = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        }
        else
        {
            NSLog(@"Error in url response");
        }
    }
    
    return self;
}

-(void) encodeParam:(NSData*) param{
    
    //rightpad
    //leftpad
    //dynamic data
}

-(NSData*) getMethodHash:(NSString *) normalizedMethodSignature{
    //TODO return KECCACK 256 of normalized method signature
    return nil;
}



@end
