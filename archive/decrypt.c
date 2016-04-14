#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

void decrypt(FILE *ifp, FILE *ofp)
{
    //Get file size
    fseek(ifp, 0L, SEEK_END);
    int fsize = ftell(ifp);
    //set back to normal
    fseek(ifp, 0L, SEEK_SET);

    int outLen1 = 0; int outLen2 = 0;
    unsigned char *indata = malloc(fsize);
    unsigned char *outdata = malloc(fsize);
    unsigned char ckey[] = "correctpasswords";
    unsigned char ivec[] = "donotchangethis!";

    //Read File
    fread(indata,sizeof(char),fsize, ifp);//Read Entire File

    //setup decryption
    EVP_CIPHER_CTX ctx;
    EVP_DecryptInit(&ctx,EVP_aes_256_cbc(),ckey,ivec);
    EVP_DecryptUpdate(&ctx,outdata,&outLen1,indata,fsize);
    EVP_DecryptFinal(&ctx,outdata + outLen1,&outLen2);
    fwrite(outdata,sizeof(char),outLen1 + outLen2,ofp);
}

int main(int argc, char *argv[])
{        
    FILE *fIN, *fOUT;
    //Decrypt file now
	if (argc != 3) {
		fprintf(stderr,  "usage: sourcefile destinationfile\n");
		exit(0);
	}
    fIN = fopen(argv[1], "rb");//File to be written; cipher text
    fOUT = fopen(argv[2], "wb");//File to be written; cipher text
    decrypt(fIN,fOUT);
    fclose(fIN);
    fclose(fOUT);

    return 0;
}
