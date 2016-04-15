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
	if(argc != 2) {
		printf("usage: AT_file\n");
		exit(0);
	}
        char message[64]; 
    FILE* atfile = fopen(argv[1], "rb");
    fseek(atfile, 0L, SEEK_END);
    int fsize = ftell(atfile);
    //set back to normal
    fseek(atfile, 0L, SEEK_SET);
    fread(message,sizeof(char),fsize, atfile);
	fclose(atfile);

        unsigned char* signature; 
        unsigned int slen; 
        unsigned int verified; 

    	FILE* pri = fopen("private.pem", "rb");
    	FILE* pub = fopen("public.pem", "rb");

        RSA *private_key; 
        RSA *public_key; 

///////////////////////////////////////////////////// 

   private_key = PEM_read_RSAPrivateKey(pri, NULL, NULL, NULL); 
   if(private_key == NULL) { 
      ERR_print_errors_fp(stdout); 
   } 
 	
	char timestamp[20];
	sprintf(timestamp, "%d", (int)time(NULL));
	printf("%s\n", timestamp); 
	strcat(message, timestamp);

        signature = (unsigned char*) malloc(RSA_size(private_key)); 
        if(RSA_sign(NID_sha1, (unsigned char*) message, strlen(message), 
signature, &slen, private_key) != 1) { 
                ERR_print_errors_fp(stdout); 
        } 

	char timefilename[128];
	strncpy(timefilename, argv[1], 127);
	strcat(timefilename, ".timestamp");
	FILE* timefile = fopen(timefilename, "w");
	fwrite(timestamp,sizeof(char),strlen(timestamp),timefile);
	fclose(timefile);
	char signfilename[128];
	strncpy(signfilename, argv[1], 127);
	strcat(signfilename, ".signed");
	FILE* signfile = fopen(signfilename, "w");
	fwrite(signature,sizeof(char),slen,signfile);
	fclose(signfile);

////////////////////////////////////////////////// 

        unsigned char signedinput[1024]; 
	unsigned char* signedoutput;
    FILE* signedfile = fopen(signfilename, "r");
    fseek(signedfile, 0L, SEEK_END);
    int fsize2 = ftell(signedfile);
    //set back to normal
    fseek(signedfile, 0L, SEEK_SET);
    fread(signedinput,sizeof(char),fsize2, signedfile);
	fclose(signedfile);

        public_key = PEM_read_RSAPublicKey(pub, NULL, NULL, NULL); 
   if(public_key == NULL) { 
      ERR_print_errors_fp(stdout); 
   } 
        verified = RSA_verify(NID_sha1, (unsigned char*) message, 
strlen(message), signedinput, 256, public_key); 

///////////////////////////////////////////////////// 

        printf("VERIFIED: %d\n",verified); 

        RSA_free(private_key); 

        RSA_free(public_key); 

        return 0; 
} 
