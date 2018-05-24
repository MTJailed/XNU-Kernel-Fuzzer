//
//  utils.c
//  XNUFuzzer
//
//  Created by Sem Voigtländer on 5/22/18.
//  Copyright © 2018 Sem Voigtländer. All rights reserved.
//

#include "utils.h"
void hexdump(unsigned char* dat, int l) {
    int i;
    for (i = 0; i < l; i++) {
        if (i!=0&&i%0x10==0) printf("\n");
        printf("%2.2x ", dat[i]);
    }
    printf("\n");
}
