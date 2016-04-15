#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/bio.h> 
#include <openssl/err.h> 
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <gf_rand.h>
#include <unistd.h>
#include "jerasure.h"
#include "reed_sol.h"
#define N 10

enum Coding_Technique {Reed_Sol_Van};

typedef struct item { 
  uint16_t arrayLen;   
  char array[2048];
  struct item *next;
} list;

/* Global variables for signal handler */
unsigned char password1[] = "correctpasswords";
unsigned char password2[] = "passwordnumber2!";
char *Methods[N] = {"reed_sol_van"};
int readins, n;
enum Coding_Technique method;
list *start = 0;
list *end = 0;

void encrypt(char* infile)
{
	char outfile[40];
	strcpy(outfile, infile);
	strcat(outfile, ".encrypted");
	printf("Encrypting file %s... ", infile);
    FILE* ifp = fopen(infile, "rb");//File to be encrypted; plain text
    FILE* ofp = fopen(outfile, "wb");//File to be written; cipher text
    //Get file size
    fseek(ifp, 0L, SEEK_END);
    int fsize = ftell(ifp);
    //set back to normal
    fseek(ifp, 0L, SEEK_SET);

    int outLen1 = 0; int outLen2 = 0;
    unsigned char *indata = malloc(fsize);
    unsigned char *outdata = malloc(fsize*2);
    unsigned char ckey[] = "donotchangethis!";
	strcpy(ckey, password1);
    unsigned char ivec[] = "donotchangethis!";

    //Read File
    fread(indata,sizeof(char),fsize, ifp);//Read Entire File

    //Set up encryption
    EVP_CIPHER_CTX ctx;
    EVP_EncryptInit(&ctx,EVP_aes_256_cbc(),ckey,ivec);
    EVP_EncryptUpdate(&ctx,outdata,&outLen1,indata,fsize);
    EVP_EncryptFinal(&ctx,outdata + outLen1,&outLen2);
    fwrite(outdata,sizeof(char),outLen1 + outLen2,ofp);

    fclose(ifp);
    fclose(ofp);
    printf("OK!\n");
}

int jfread(void *ptr, int size, int nmembers, FILE *stream)
{
  if (stream != NULL) return fread(ptr, size, nmembers, stream);

  MOA_Fill_Random_Region(ptr, size);
  return size;
}

int rs_encode (int argc, char **argv, char* metafilename) {
	FILE *fp, *fp2;				// file pointers
	char *block;				// padding file
	int size, newsize;			// size of file and temp size 
	struct stat status;			// finding file size

	
	enum Coding_Technique tech;		// coding technique (parameter)
	int k, m, w, packetsize;		// parameters
	int buffersize;					// paramter
	int i;						// loop control variables
	int blocksize;					// size of k+m files
	int total;
	int extra;
	
	/* Jerasure Arguments */
	char **data;				
	char **coding;
	int *matrix;
	
	/* Creation of file name variables */
	char temp[5];
	char *s1, *s2, *extension;
	char *fname;
	int md;
	char *curdir;

	/* Find buffersize */
	int up, down;

	matrix = NULL;
	
	/* Error check Arguments*/
	if (argc != 5) {
		fprintf(stderr,  "usage: inputfile k m w\n");
		fprintf(stderr,  "\nBuffersize of 0 means the buffersize is chosen automatically.\n");
		exit(0);
	}
	/* Conversion of parameters and error checking */	
	if (sscanf(argv[2], "%d", &k) == 0 || k <= 0) {
		fprintf(stderr,  "Invalid value for k\n");
		exit(0);
	}
	if (sscanf(argv[3], "%d", &m) == 0 || m < 0) {
		fprintf(stderr,  "Invalid value for m\n");
		exit(0);
	}
	if (sscanf(argv[4],"%d", &w) == 0 || w <= 0) {
		fprintf(stderr,  "Invalid value for w.\n");
		exit(0);
	}
	if (argc == 5) {
		packetsize = 0;
		buffersize = 0;
	}

	/* Setting of coding technique and error checking */
	tech = Reed_Sol_Van;

	/* Set global variable method for signal handler */
	method = tech;

	/* Get current working directory for construction of file names */
	curdir = (char*)malloc(sizeof(char)*1000);	
	assert(curdir == getcwd(curdir, 1000));

        if (argv[1][0] != '-') {

		/* Open file and error check */
		fp = fopen(argv[1], "rb");
		if (fp == NULL) {
			fprintf(stderr,  "Unable to open file.\n");
			exit(0);
		}
		
		/* Create Coding directory 
		i = mkdir("Coding", S_IRWXU);
		if (i == -1 && errno != EEXIST) {
			fprintf(stderr, "Unable to create Coding directory.\n");
			exit(0);
		}*/
	
		/* Determine original size of file */
		stat(argv[1], &status);	
		size = status.st_size;
        } else {
        	if (sscanf(argv[1]+1, "%d", &size) != 1 || size <= 0) {
                	fprintf(stderr, "Files starting with '-' should be sizes for randomly created input\n");
			exit(1);
		}
        	fp = NULL;
		MOA_Seed(time(0));
        }

	newsize = size;
	
	/* Find new size by determining next closest multiple */
	if (packetsize != 0) {
		if (size%(k*w*packetsize*sizeof(long)) != 0) {
			while (newsize%(k*w*packetsize*sizeof(long)) != 0) 
				newsize++;
		}
	}
	else {
		if (size%(k*w*sizeof(long)) != 0) {
			while (newsize%(k*w*sizeof(long)) != 0) 
				newsize++;
		}
	}
	
	if (buffersize != 0) {
		while (newsize%buffersize != 0) {
			newsize++;
		}
	}


	/* Determine size of k+m files */
	blocksize = newsize/k;

	/* Allow for buffersize and determine number of read-ins */
	if (size > buffersize && buffersize != 0) {
		if (newsize%buffersize != 0) {
			readins = newsize/buffersize;
		}
		else {
			readins = newsize/buffersize;
		}
		block = (char *)malloc(sizeof(char)*buffersize);
		blocksize = buffersize/k;
	}
	else {
		readins = 1;
		buffersize = size;
		block = (char *)malloc(sizeof(char)*newsize);
	}
	
	/* Break inputfile name into the filename and extension */	
	s1 = (char*)malloc(sizeof(char)*(strlen(argv[1])+20));
	s2 = strrchr(argv[1], '/');
	if (s2 != NULL) {
		s2++;
		strcpy(s1, s2);
	}
	else {
		strcpy(s1, argv[1]);
	}
	s2 = strchr(s1, '.');
	if (s2 != NULL) {
          extension = strdup(s2);
          *s2 = '\0';
	} else {
          extension = strdup("");
        }
	
	/* Allocate for full file name */
	fname = (char*)malloc(sizeof(char)*(strlen(argv[1])+strlen(curdir)+20));
	sprintf(temp, "%d", k);
	md = strlen(temp);
	
	/* Allocate data and coding */
	data = (char **)malloc(sizeof(char*)*k);
	coding = (char **)malloc(sizeof(char*)*m);
	for (i = 0; i < m; i++) {
		coding[i] = (char *)malloc(sizeof(char)*blocksize);
                if (coding[i] == NULL) { perror("malloc"); exit(1); }
	}

	

	/* Create coding matrix or bitmatrix */
	matrix = reed_sol_vandermonde_coding_matrix(k, m, w);

	

	/* Read in data until finished */
	n = 1;
	total = 0;

	while (n <= readins) {
		/* Check if padding is needed, if so, add appropriate 
		   number of zeros */
		if (total < size && total+buffersize <= size) {
			total += jfread(block, sizeof(char), buffersize, fp);
		}
		else if (total < size && total+buffersize > size) {
			extra = jfread(block, sizeof(char), buffersize, fp);
			for (i = extra; i < buffersize; i++) {
				block[i] = '0';
			}
		}
		else if (total == size) {
			for (i = 0; i < buffersize; i++) {
				block[i] = '0';
			}
		}
	
		/* Set pointers to point to file data */
		for (i = 0; i < k; i++) {
			data[i] = block+(i*blocksize);
		}

		/* Encode according to coding method */
		jerasure_matrix_encode(k, m, w, matrix, data, coding, blocksize);
	
		/* Write data and encoded data to k+m files */
		for	(i = 1; i <= k; i++) {
			if (fp == NULL) {
				bzero(data[i-1], blocksize);
 			} else {
				sprintf(fname, "%s_k%0*d%s", s1, md, i, extension);
				if (n == 1) {
					fp2 = fopen(fname, "wb");
				}
				else {
					fp2 = fopen(fname, "ab");
				}
				fwrite(data[i-1], sizeof(char), blocksize, fp2);
				fclose(fp2);
			}
			
		}
		for	(i = 1; i <= m; i++) {
			if (fp == NULL) {
				bzero(data[i-1], blocksize);
 			} else {
				sprintf(fname, "%s_m%0*d%s", s1, md, i, extension);
				if (n == 1) {
					fp2 = fopen(fname, "wb");
				}
				else {
					fp2 = fopen(fname, "ab");
				}
				fwrite(coding[i-1], sizeof(char), blocksize, fp2);
				fclose(fp2);
  				encrypt(fname);
			}
		}
		n++;
	}

	/* Create metadata file */
        if (fp != NULL) {
		sprintf(fname, "%s_meta.txt", s1);
		sprintf(metafilename, "%s_meta.txt", s1);
		fp2 = fopen(fname, "wb");
		fprintf(fp2, "%s\n", argv[1]);
		fprintf(fp2, "%d\n", size);
		fprintf(fp2, "%d %d %d %d %d\n", k, m, w, packetsize, buffersize);
		fprintf(fp2, "%s\n", argv[4]);
		fprintf(fp2, "%d\n", tech);
		fprintf(fp2, "%d\n", readins);
		fclose(fp2);
  		encrypt(fname);
	}


	/* Free allocated memory */
	free(s1);
	free(fname);
	free(block);
	free(curdir);
	
	printf("Encoded files have been created.\n");

	return 0;
}

void generate_keys()
{
    	if(access("public.pem", F_OK) != -1 && access("private.pem", F_OK) != -1) {
		printf("Keys already exist\n");
		return;
	}
    int ret = 0;
    RSA *r = NULL;
    BIGNUM *bne = NULL;
    BIO *bp_public = NULL, *bp_private = NULL;
    int bits = 2048;
    unsigned long e = RSA_F4;
 
    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne,e);
    if(ret != 1){
        goto free_all;
    }
 
    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if(ret != 1){
        goto free_all;
    }
 
    // 2. save public key
    bp_public = BIO_new_file("public.pem", "w+");
    ret = PEM_write_bio_RSAPublicKey(bp_public, r);
    if(ret != 1){
        goto free_all;
    }
 
    // 3. save private key
    bp_private = BIO_new_file("private.pem", "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
 
    // 4. free
free_all:
 
    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(r);
    BN_free(bne);
 
    if(ret == 0) {
	printf("Key pair generation failed..\n");
	printf("Exiting program!\n");
	exit(0);
    } else {
	printf("Key pair generation successful!\n");
    }
}

void generateRandomString(char* randomString, int size) {
	int i = 0;
	char* alphanum[] = {"1234567890", 
				"!@#$%^&*()", 					"ABCDEFGHIJKLMNOPQRSTUVWXYZ", 					"abcdefghijklmnopqrstuvwxyz"};
	srand(time(NULL));
	for(i = 0; i < size; i++) {
		char* rand_set = alphanum[rand() % (sizeof(alphanum) / 4)];
		randomString[i] = rand_set[rand() % strlen(rand_set)];
	}
	randomString[size] = '\0';
}

void serializeList(list *item, char *buffer)
{
  int seeker = 0;  
  
  while(item != NULL)
  {

    memcpy(&buffer[seeker], &item->arrayLen, sizeof(item->arrayLen));
    seeker += sizeof(item->arrayLen); 

    memcpy(&buffer[seeker], &item->array, item->arrayLen);
    seeker += item->arrayLen; 

    item = item->next; 
  }
}

int listSize(list *item)
{
  int size = 0;
  
  while (item != 0) {
    size += item->arrayLen;        
    size += sizeof(item->arrayLen); 
    item = item->next;         
  }
  return size;
}

void createSecretPackage(char* ip, char* saltvalue, char* randomString, char* privatekey, char* metafilecontents) {
  list *ptr;         
  char *buffer;         
  int listLength;        
  list ips, salt, secret, private, metafilec;
  ptr = &ips;             
  
  FILE *filePtr;          

  strcpy(ips.array, ip);
  ips.arrayLen = strlen(ips.array);
  ips.next = &salt;
  					    
  strcpy(salt.array, saltvalue);
  salt.arrayLen = strlen(salt.array);
  salt.next = &metafilec;	

  strcpy(metafilec.array, metafilecontents);
  metafilec.arrayLen = strlen(metafilec.array);
  metafilec.next = &secret;
	    
  strcpy(secret.array, randomString);
  secret.arrayLen = strlen(secret.array);
  secret.next = &private;
  
  strcpy(private.array, privatekey);
  private.arrayLen = strlen(private.array);
  private.next = 0;

  
  listLength = listSize(ptr);
  
  buffer = (char *)malloc(listLength);
  
  serializeList(ptr, buffer);
  
  filePtr = fopen("secretpackage.data", "wb+"); 

  fwrite(buffer, listLength, 1, filePtr);
  					  
  fclose(filePtr); 
  printf("Secret Package has been created (secretpackage.data)\n");
  encrypt("secretpackage.data");
  free(buffer); 
}

void createSecretKeyFile(char* randomString) {
    FILE *file = fopen("secretkey.data", "wb");
    fwrite(randomString,sizeof(char),strlen(randomString),file);
    fclose(file);
    printf("Secret Key file has been created (secretkey.data)\n");
}

void getPrivateKey(char* privatekey) {
	FILE *fp;
	long lSize;
	char tmp[2048];
	memset(tmp, 0, sizeof(tmp));
	
	fp = fopen ( "private.pem" , "rb" );
	if( !fp ) perror("private.pem"),exit(1);

	fseek( fp , 0L , SEEK_END);
	lSize = ftell( fp );
	rewind( fp );

	if( 1!=fread( tmp , lSize, 1 , fp) )
	fclose(fp),fputs("Unable to read private.pem",stderr),exit(1);

	memcpy(privatekey, (tmp+32), strlen(tmp) - 63);
	privatekey[strlen(tmp) - 63] = '\0';

	fclose(fp);
    	/*FILE *fOUT;
	fOUT = fopen("privatekey.data", "wb");
    	fwrite(privatekey,sizeof(char),strlen(privatekey),fOUT);
	fclose(fOUT);*/
}

void getPublicKey(char* publickey) {
	FILE *fp;
	long lSize;
	char tmp[2048];
	memset(tmp, 0, sizeof(tmp));

	fp = fopen ( "public.pem" , "rb" );
	if( !fp ) perror("public.pem"),exit(1);

	fseek( fp , 0L , SEEK_END);
	lSize = ftell( fp );
	rewind( fp );

	if( 1!=fread( tmp , lSize, 1 , fp) )
	fclose(fp),fputs("Unable to read public.pem",stderr),exit(1);
	
	memcpy(publickey, (tmp+31), strlen(tmp) - 61);
	publickey[strlen(tmp) - 61] = '\0';

	fclose(fp);
    	/*FILE *fOUT;
	fOUT = fopen("publickey.data", "wb");
    	fwrite(publickey,sizeof(char),strlen(publickey),fOUT);
	fclose(fOUT);*/
}

void getSecretKey(char* secretkey) {
	FILE *fp;
	long lSize;
	char tmp[2048];
	memset(tmp, 0, sizeof(tmp));

	fp = fopen ( "secretkey.data" , "rb" );
	if( !fp ) { 
		generateRandomString(tmp, 256);
		createSecretKeyFile(tmp); 
		fp = fopen ( "secretkey.data" , "rb" );
	}

	fseek( fp , 0L , SEEK_END);
	lSize = ftell( fp );
	rewind( fp );

	if( 1!=fread( tmp , lSize, 1 , fp) )
	fclose(fp),fputs("Unable to read secretkey.data",stderr),exit(1);
	
	memcpy(secretkey, tmp, strlen(tmp));
	secretkey[strlen(tmp)] = '\0';

	fclose(fp);
}

void AT_sign(char* ATfile) {
        char message[64]; 
	FILE* atfile = fopen(ATfile, "rb");
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
	private_key = PEM_read_RSAPrivateKey(pri, NULL, NULL, NULL); 
   if(private_key == NULL) { 
      ERR_print_errors_fp(stdout); 
   } 
 	
	char timestamp[20];
	sprintf(timestamp, "%d", (int)time(NULL));
	strcat(message, timestamp);

        signature = (unsigned char*) malloc(RSA_size(private_key)); 
        if(RSA_sign(NID_sha1, (unsigned char*) message, strlen(message), 
signature, &slen, private_key) != 1) { 
                ERR_print_errors_fp(stdout); 
        } 

	char timefilename[128];
	strncpy(timefilename, ATfile, 127);
	strcat(timefilename, ".timestamp");
	FILE* timefile = fopen(timefilename, "w");
	fwrite(timestamp,sizeof(char),strlen(timestamp),timefile);
	fclose(timefile);
	char signfilename[128];
	strncpy(signfilename, ATfile, 127);
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

	printf("Authentication Token signed - VERIFIED: %d\n",verified);

        RSA_free(private_key); 

        RSA_free(public_key); 
}

void AT(char* sk, char* salt, char* IP) {
	unsigned char at[512];
	strcat(at, sk);
	strcat(at, password2);
	strcat(at, salt);
   	int i = 0;
    	unsigned char temp[SHA_DIGEST_LENGTH];
    	char buf[SHA_DIGEST_LENGTH*2];

    	memset(buf, 0x0, SHA_DIGEST_LENGTH*2);
    	memset(temp, 0x0, SHA_DIGEST_LENGTH);

	SHA1((unsigned char *)at, strlen(at), temp);

	for (i=0; i < SHA_DIGEST_LENGTH; i++) {
	        sprintf((char*)&(buf[i*2]), "%02x", temp[i]);
   	}

    	FILE *ATout;
	char ATfile[30];
	strcat(ATfile, "AT");
	strcat(ATfile, IP);
	strcat(ATfile, ".data");
	ATout = fopen(ATfile, "wb");
    	fwrite(buf,sizeof(char),strlen(buf),ATout);
	fclose(ATout);
	printf("Authentication Token created for %s\n", IP);
	AT_sign(ATfile);
}

void getMetafileContents(char* metafilename, char* metafilecontents) {    
    FILE *file = fopen(metafilename, "rb");
    fseek(file, 0L, SEEK_END);
    int fsize = ftell(file);
    fseek(file, 0L, SEEK_SET);

    fread(metafilecontents,sizeof(char),fsize, file);
	metafilecontents[fsize] = '\0';
}

int main(int argc, char* argv[]) 
{
	if(argc > 5) {
		char* encodeInput[5] = {"", argv[1], argv[2], argv[3], argv[4]};
		char metafilename[128];
		char randomString[260];
		char privatekey[2048];
		char publickey[2048];
		char ip[20];
		char salt[20];
		char metafilecontents[2048];
		rs_encode(5, encodeInput, metafilename);
		srand(time(NULL));
		//char* ip[argc - 5];
		//char* salt[argc - 5];
		strncpy(ip, argv[5], 20);
		//sprintf(salt, "%d", (rand() % 5) + 1);
		strcpy(salt, ip);
		getMetafileContents(metafilename, metafilecontents);
	    	generate_keys();
		getSecretKey(randomString);
		getPrivateKey(privatekey);
		getPublicKey(publickey);
		createSecretPackage(ip, salt, randomString, privatekey, metafilecontents);
		AT(randomString, salt, ip);
	} else {		
		printf("usage: inputfile k m w <IP_addresses>\n");
		exit(0);
	}
        return 0;
}




