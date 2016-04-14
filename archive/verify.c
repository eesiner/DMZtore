#include <stdio.h> 
#include <stdlib.h> 
#include <stdint.h> 
#include <string.h> 
#include <time.h>

#include <openssl/bio.h> 
#include <openssl/rsa.h> 
#include <openssl/pem.h> 
#include <openssl/err.h> 

int main(int argc, char *argv[]) 
{ 
	if(argc != 3) {
		printf("usage: <AT file> <.timestamp file>\n");
		exit(0);
	}
    	FILE* pub = fopen("public.pem", "rb");

        RSA *public_key; 
	int verified = 0;
        char message[64]; 

////////////////////////////////////////////////// 

        unsigned char atinput[1024]; 
    FILE* atfile = fopen(argv[1], "r");
    fseek(atfile, 0L, SEEK_END);
    int fsize = ftell(atfile);
    //set back to normal
    fseek(atfile, 0L, SEEK_SET);
    fread(atinput,sizeof(char),fsize, atfile);
	fclose(atfile);


	char timestamp[20];
	FILE* tsfile = fopen(argv[2], "r");
    fseek(tsfile, 0L, SEEK_END);
    int fsize2 = ftell(tsfile);
    //set back to normal
    fseek(tsfile, 0L, SEEK_SET);
    fread(timestamp,sizeof(char),fsize2, tsfile);
	fclose(tsfile);
	strcat(atinput, timestamp);


	char signedinput[1024];
	FILE* signedfile = fopen("AT127.0.0.1_10000.data.signed", "r");
    fseek(signedfile, 0L, SEEK_END);
    int fsize3 = ftell(signedfile);
    //set back to normal
    fseek(signedfile, 0L, SEEK_SET);
    fread(signedinput,sizeof(char),fsize3, signedfile);
	fclose(signedfile);


        public_key = PEM_read_RSAPublicKey(pub, NULL, NULL, NULL); 
   if(public_key == NULL) { 
      ERR_print_errors_fp(stdout); 
   } 
        verified = RSA_verify(NID_sha1, (unsigned char*) atinput, 
strlen(atinput), signedinput, 256, public_key); 

///////////////////////////////////////////////////// 

        printf("VERIFIED: %d\n",verified); 

        RSA_free(public_key); 

        return 0; 
} 
