#include <string.h>
#include "lzss.h"

void lzssDecompress(const uint8_t *src, uint8_t *dst, int size) {
    unsigned char flags = 0;
    unsigned char mask  = 0;
    unsigned int  len;
    unsigned int  disp;
    
    while(size > 0) {
        if(mask == 0) {
            // read in the flags data
            // from bit 7 to bit 0:
            //     0: raw byte
            //     1: compressed block
            flags = *src++;
            mask  = 0x80;
        }
        
        if(flags & mask) { // compressed block
            // disp: displacement
            // len:  length
            len  = (((*src)&0xF0)>>4)+3;
            disp = ((*src++)&0x0F);
            disp = disp<<8 | (*src++);
            
            size -= len;
            
            // for len, copy data from the displacement
            // to the current buffer position
            memcpy(dst, dst-disp-1, len);
            dst += len;
        }
        else { // uncompressed block
            // copy a raw byte from the input to the output
            *dst++ = *src++;
            size--;
        }
        
        mask >>= 1;
    }
}
