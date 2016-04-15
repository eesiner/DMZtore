#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

void encrypt(FILE *ifp, FILE *ofp)
{
	/* Start timing */
	clock_t begin, end;
	double time_spent;
	begin = clock();

    //Get file size
    fseek(ifp, 0L, SEEK_END);
    int fsize = ftell(ifp);
    //set back to normal
    fseek(ifp, 0L, SEEK_SET);

    int outLen1 = 0; int outLen2 = 0;
    unsigned char *indata = malloc(fsize);
    unsigned char *outdata = malloc(fsize*2);
    unsigned char ckey[] =  "password";
    unsigned char ivec[] = "donotchangethis!";

    //Read File
    fread(indata,sizeof(char),fsize, ifp);//Read Entire File

    //Set up encryption
    EVP_CIPHER_CTX ctx;
    EVP_EncryptInit(&ctx,EVP_aes_256_cbc(),ckey,ivec);
    EVP_EncryptUpdate(&ctx,outdata,&outLen1,indata,fsize);
    EVP_EncryptFinal(&ctx,outdata + outLen1,&outLen2);
    fwrite(outdata,sizeof(char),outLen1 + outLen2,ofp);

	end = clock();
	time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	printf("Time taken to encrypt: %g ms\n", time_spent * 1000);

}

int main(int argc, char *argv[])
{        
    FILE *fIN, *fOUT;
	if (argc != 3) {
		fprintf(stderr,  "usage: sourcefile destinationfile\n");
		exit(0);
	}
    fIN = fopen(argv[1], "rb");//File to be encrypted; plain text
    fOUT = fopen(argv[2], "wb");//File to be written; cipher text

    encrypt(fIN, fOUT);
    fclose(fIN);
    fclose(fOUT);
    return 0;
}
