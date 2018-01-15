//
//  Contract+Contract.m
//  Secp256k1-Test
//
//  Created by Amit Shah on 2018-01-04.
//  Copyright © 2018 Amit Shah. All rights reserved.
//

#import "Contract.h"
#import "tommath.h"
#import "Transaction.h"
#import "NSNumber+BigNumber.h"

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


//encode a uint<8,16,32,256>
+(NSData*) encodeUInt:(int)i withN:( int) length{
    
    mp_int bi;
    mp_init_set(&bi, i);
    char * hex;
    int size;
    if(!mp_radix_size(&bi, 16, &size)){
        raise(0);
    }
    mp_toradix_n(&bi, hex, 16, length);
    //TODO you have to pad this bitch
    return dataFromChar(hex, size);
}


+(NSData*) encodeUINTN:(mp_int)i withSize:( int) length{
    char * hex;
    int size;
    if(!mp_radix_size(&i, 16, &size)){
        raise(0);
    }
    mp_toradix_n(&i, hex, 16, length);
    return dataFromChar(hex, size);
}

-(NSData*) encodeAddress:(NSString*)address{
    return [NSData dataWithBytes:[address UTF8String] length:20];
}


-(NSData *) zeroData: (int) length {
    return [NSMutableData dataWithLength:length];
    
}

+(int) parseN: (NSString*) typeN{
    NSRegularExpression *sizeN = [NSRegularExpression regularExpressionWithPattern:@"^(bytes|uint)(\d+)$" options:NSRegularExpressionSearch error:nil];
    NSArray *matches = [sizeN matchesInString:typeN options:0 range:NSMakeRange(0,[typeN length])];
    if([matches count] == 2){
        NSRange matchRange = [matches[1] rangeAtIndex:1];
        NSString *matchString = [typeN substringWithRange:matchRange];
        return [[NSNumber numberWithChar:[matchString UTF8String]] integerValue];
    }
    return 0;
}



-(NSMutableData *) createBuffer: (int) size forType:(nullable NSString*) typeN{

    if(typeN){
        return [NSMutableData dataWithLength:[Contract parseN:typeN]];
    }
    return [NSMutableData dataWithLength:size];
}



//Address passed as NSString with NO 0x prefix
//bool passed as boolean
//bytes and bytes<n> passed as NSString with NO 0x prefix

//ARG
//UINTN => NSNumber setBigIntValue
// Bytes => NSSTring hexEncoded no 0x
// String => plain string
//address => NSString hexEncoded no 0x

-(NSData*) encodeSingle: (NSString*) type withArg:(id) arg{
    if([type isEqualToString:@"address"]){
        return [self encodeAddress:(NSString *)arg];
    }
    else if([type isEqualToString:@"bool"]){
        bool t = (Boolean)arg;
        dataWithByte(t);
        //assumed to be zeroed out
        return [NSData dataWithBytes:NULL length:1];
        
        
    }else if([type isEqualToString:@"string"]){
        
        NSData * dataString = [NSData dataWithData:[(NSString*)arg dataUsingEncoding:NSUTF8StringEncoding] ];
        NSMutableData * b =  [NSMutableData dataWithData:[self encodeSingle:@"uint256" withArg:[NSNumber numberWithInt:[(NSString*)dataString length]]]];
        [b appendData:dataString];
        //pad right
        if([b length] % 32 != 0){
            [b appendData:[self zeroData:32 - ((int)[b length]%32)] ];
        }
        NSLog(@"STRING:%@", [NSString hexStringWithData:[b bytes] ofLength:[b length]]);
        return b;
    }
    else if([type isEqualToString:@"bytes"]){
        //NSData from hex encoded byte string
        NSData * data =dataFromChar([(NSString*)arg UTF8String], (uint)[(NSString*)arg length] );
        NSMutableData * b =  [NSMutableData dataWithData:[self encodeSingle:@"uint256" withArg:[NSNumber numberWithInt:[data length]]]];
        [b appendData:data];
        if([b length] % 32 !=0){
            [b appendData:[self zeroData:32 - ((int)[b length]%32)] ];
        }
        NSLog(@"BYTES:%@", [NSString hexStringWithData:[b bytes] ofLength:[b length]]);
        return b;
    }else if ([type hasPrefix:@"uint"]){
        NSMutableData* d = [NSMutableData dataWithLength:32];
        NSData* dataInt = [(NSNumber *)arg getData];
        [d replaceBytesInRange:NSMakeRange(32-[dataInt length], [dataInt length]) withBytes:dataInt.bytes];
        NSLog(@"%@", [NSString hexStringWithData:[d bytes] ofLength:[d length]]);
        return d;
        
    }else{
        if([arg isKindOfClass:[NSMutableArray class]] ||[arg isKindOfClass:[NSArray class]] ){
            // This is a nsmutable array
            NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"/(\w+\)[(\d*\)]/" options:NSRegularExpressionSearch error:NULL];
            NSArray *matches = [regex matchesInString:type options:0 range:NSMakeRange(0,[type length])];
            if(matches){
                NSArray * arrayArg = (NSArray*) arg;
                NSMutableData * ret = [NSMutableData init];
                NSRange typeRange = [matches[0] rangeAtIndex:1];
                NSString *typeN = [type substringWithRange:typeRange];
                //TODO: safety check to ensure correct number of arrays passed to static sized array param
                [ret appendData:[self encodeSingle: @"uint256" withArg:[NSNumber numberWithInt:[arrayArg count] ]]];
                for(NSObject* o in arrayArg){
                    [ret appendData:[self encodeSingle: typeN withArg:o]];
                }
                return ret;
//                if([matches count] ==2){
//                    
//                    [ret appendData:[self encodeSingle: @"uint256" withArg:[NSNumber numberWithInt:[arrayArg count] ]]];
//                     for(NSObject* o in arrayArg){
//                         [ret appendData:[self encodeSingle: typeN withArg:o]];
//                     }
//                     return ret;
//                }else{
//                    NSArray * data = (NSArray*)arg;
//                    for(NSObject * d in data){
//                        [self encodeSingle:matches[0] withArg:d];
//                    }
//                }
            }
        }
    }
    
       

    
    //TODO handle array
    
    
    //        return encodeSingle('bytes', new Buffer(arg, 'utf8'))
    //    } else if (type.match(/\w+\[\d+\]/)) {
    //        // this part handles fixed-length arrays ([2])
    //        // NOTE: we catch here all calls to arrays, that simplifies the rest
    //        if (typeof arg.length === 'undefined') {
    //            throw new Error('Not an array?')
    //        }
    //
    //        size = parseTypeArray(type)
    //        if ((size !== 0) && (arg.length > size)) {
    //            throw new Error('Elements exceed array size: ' + size)
    //        }
    //
    //        type = type.slice(0, type.indexOf('['))
    //
    //        ret = []
    //        for (i in arg) {
    //            ret.push(encodeSingle(type, arg[i]))
    //        }
    //
    //        return Buffer.concat(ret)
    //    } else if (type.match(/\w+\[\]/)) {
    //        // this part handles variable length ([])
    //        // NOTE: we catch here all calls to arrays, that simplifies the rest
    //        if (typeof arg.length === 'undefined') {
    //            throw new Error('Not an array?')
    //        }
    //
    //        type = type.slice(0, type.indexOf('['))
    //
    //        ret = [ encodeSingle('uint256', arg.length) ]
    //        for (i in arg) {
    //            ret.push(encodeSingle(type, arg[i]))
    //        }
    //
    //        return Buffer.concat(ret)
    //    } else if (type === 'bytes') {
    //        arg = new Buffer(arg)
    //
    //        ret = Buffer.concat([ encodeSingle('uint256', arg.length), arg ])
    //
    //        if ((arg.length % 32) !== 0) {
    //            ret = Buffer.concat([ ret, utils.zeros(32 - (arg.length % 32)) ])
    //        }
    //
    //        return ret
    //    } else if (type.startsWith('bytes')) {
    //        size = parseTypeN(type)
    //        if (size < 1 || size > 32) {
    //            throw new Error('Invalid bytes<N> width: ' + size)
    //        }
    //
    //        return utils.setLengthRight(arg, 32)
    //    } else if (type.startsWith('uint')) {
    //        size = parseTypeN(type)
    //        if ((size % 8) || (size < 8) || (size > 256)) {
    //            throw new Error('Invalid uint<N> width: ' + size)
    //        }
    //
    //        num = parseNumber(arg)
    //        if (num.bitLength() > size) {
    //            throw new Error('Supplied uint exceeds width: ' + size + ' vs ' + num.bitLength())
    //        }
    //
    //        if (num < 0) {
    //            throw new Error('Supplied uint is negative')
    //        }
    //
    //        return num.toArrayLike(Buffer, 'be', 32)
    //    } else if (type.startsWith('int')) {
    //        size = parseTypeN(type)
    //        if ((size % 8) || (size < 8) || (size > 256)) {
    //            throw new Error('Invalid int<N> width: ' + size)
    //        }
    //
    //        num = parseNumber(arg)
    //        if (num.bitLength() > size) {
    //            throw new Error('Supplied int exceeds width: ' + size + ' vs ' + num.bitLength())
    //        }
    //
    //        return num.toTwos(256).toArrayLike(Buffer, 'be', 32)
    //    } else if (type.startsWith('ufixed')) {
    //        size = parseTypeNxM(type)
    //
    //        num = parseNumber(arg)
    //
    //        if (num < 0) {
    //            throw new Error('Supplied ufixed is negative')
    //        }
    //        
    //        return encodeSingle('uint256', num.mul(new BN(2).pow(new BN(size[1]))))
    //    } else if (type.startsWith('fixed')) {
    //        size = parseTypeNxM(type)
    //        
    //        return encodeSingle('int256', parseNumber(arg).mul(new BN(2).pow(new BN(size[1]))))
    //    }
    //    
    //    throw new Error('Unsupported or invalid type: ' + type)
    //}

    return nil;
}

-(bool) isDynamic: (NSString*) type{
    return [type isEqualToString:@"bytes"] || [type isEqualToString:@"string"] ;
    //return false;
}

- (NSString*) normalizeType: (NSString *) type{
    //TODO normalize type implementation
    return @"uint256";
}

-(NSData *) rawEncode: (NSArray*) types withVals: (NSArray*) values {
    
    NSMutableData* output = [NSMutableData alloc];
    
    NSMutableData* data = [NSMutableData alloc];
    
    uint headLength = 32 * [types count];
    for (int i = 0; i < [types count]; i++)
    {
        
        NSString * type = [types objectAtIndex:i];
        NSData* encoded = [self encodeSingle:type withArg:[values objectAtIndex:i]];
        if([self isDynamic:type]){
            //for dynamic types
            
            [output appendData:[self encodeSingle:@"uint256" withArg: [NSNumber numberWithInt:headLength]]];
            [data appendData:encoded];
            headLength += [encoded length];
        }else{
            [output appendData:encoded];
        }
        
        
        
    }
    //we use head-tail encoding
    [output appendData:data];
    return output;
//    for (NSString* t in types) {
//        NSString * type = [elementaryName t];
//        var value = values[i]
//        var cur = encodeSingle(type, value)
//        
//        // Use the head/tail method for storing dynamic data
//        if (isDynamic(type)) {
//            output.push(encodeSingle('uint256', headLength))
//            data.push(cur)
//            headLength += cur.length
//        } else {
//            output.push(cur)
//        }
//    }
//    
//    return Buffer.concat(output.concat(data))
}
                


-(NSData*) getMethodHash:(NSString *) normalizedMethodSignature{
    //TODO return KECCACK 256 of normalized method signature
    return nil;
}



@end
