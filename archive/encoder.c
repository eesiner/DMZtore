/*
This program takes as input an inputfile, k, m, a coding 
technique, w, and packetsize.  It creates k+m files from 
the original file so that k of these files are parts of 
the original file and m of the files are encoded based on 
the given coding technique. The format of the created files 
is the file name with "_k#" or "_m#" and then the extension.  
(For example, inputfile test.txt would yield file "test_k1.txt".)
*/

#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <gf_rand.h>
#include <unistd.h>
#include "jerasure.h"
#include "reed_sol.h"
#include "timing.h"

#define N 10

enum Coding_Technique {Reed_Sol_Van};

char *Methods[N] = {"reed_sol_van"};

/* Global variables for signal handler */
int readins, n;
enum Coding_Technique method;

void ctrl_bs_handler(int dummy);

int jfread(void *ptr, int size, int nmembers, FILE *stream)
{
  if (stream != NULL) return fread(ptr, size, nmembers, stream);

  MOA_Fill_Random_Region(ptr, size);
  return size;
}


int main (int argc, char **argv) {
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

	/* Start timing */
	clock_t begin, end;
	double time_spent;
	begin = clock();

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
			}
		}
		n++;
	}

	end = clock();
	time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	struct stat st;
	stat(argv[1], &st);
	size = st.st_size;
	printf("Time taken to encode %d bytes: %g ms\n", size, time_spent * 1000);

	/* Create metadata file */
        if (fp != NULL) {
		sprintf(fname, "%s_meta.txt", s1);
		fp2 = fopen(fname, "wb");
		fprintf(fp2, "%s\n", argv[1]);
		fprintf(fp2, "%d\n", size);
		fprintf(fp2, "%d %d %d %d %d\n", k, m, w, packetsize, buffersize);
		fprintf(fp2, "%s\n", argv[4]);
		fprintf(fp2, "%d\n", tech);
		fprintf(fp2, "%d\n", readins);
		fclose(fp2);
	}


	/* Free allocated memory */
	free(s1);
	free(fname);
	free(block);
	free(curdir);
	
	return 0;
}

