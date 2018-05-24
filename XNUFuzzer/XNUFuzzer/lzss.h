//
//  lzss.h
//  XNUFuzzer
//
//  Created by Sem Voigtländer on 5/22/18.
//  Copyright © 2018 Sem Voigtländer. All rights reserved.
//

#ifndef lzss_h
#define lzss_h

#include <stdio.h>
void lzssDecompress(const uint8_t *src, uint8_t* dst, int size);
#endif /* lzss_h */
