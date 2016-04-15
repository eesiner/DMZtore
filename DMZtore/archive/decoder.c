/* 
This program takes as input an inputfile, k, m, a coding
technique, w, and packetsize.  It is the companion program
of encoder.c, which creates k+m files.  This program assumes 
that up to m erasures have occurred in the k+m files.  It
reads in the k+m files or marks the file as erased. It then
recreates the original file and creates a new file with the
suffix "decoded" with the decoded contents of the file.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include "jerasure.h"
#include "reed_sol.h"

#define N 10

enum Coding_Technique {Reed_Sol_Van};

char *Methods[N] = {"reed_sol_van"};

/* Global variables for signal handler */
enum Coding_Technique method;
int readins, n;

int main (int argc, char **argv) {
	FILE *fp;				// File pointer

	/* Jerasure arguments */
	char **data;
	char **coding;
	int *erasures;
	int *erased;
	int *matrix;
	int *bitmatrix;
	
	/* Parameters */
	int k, m, w, packetsize, buffersize;
	int tech;
	char *c_tech;
	
	int i, j;				// loop control variable, s
	int blocksize = 0;			// size of individual files
	int origsize;			// size of file before padding
	int total;				// used to write data, not padding to file
	struct stat status;		// used to find size of individual files
	int numerased;			// number of erased files
		
	/* Used to recreate file names */
	char *temp;
	char *cs1, *cs2, *extension;
	char *fname;
	int md;
	char *curdir;


	matrix = NULL;
	bitmatrix = NULL;

	/* Error checking parameters */
	if (argc != 2) {
		fprintf(stderr, "usage: inputfile\n");
		exit(0);
	}
	curdir = (char *)malloc(sizeof(char)*1000);
	assert(curdir == getcwd(curdir, 1000));
	
	/* Begin recreation of file names */
	cs1 = (char*)malloc(sizeof(char)*strlen(argv[1]));
	cs2 = strrchr(argv[1], '/');
	if (cs2 != NULL) {
		cs2++;
		strcpy(cs1, cs2);
	}
	else {
		strcpy(cs1, argv[1]);
	}
	cs2 = strchr(cs1, '.');
	if (cs2 != NULL) {
                extension = strdup(cs2);
		*cs2 = '\0';
	} else {
           extension = strdup("");
        }	
	fname = (char *)malloc(sizeof(char*)*(100+strlen(argv[1])+20));

	/* Read in parameters from metadata file */
	sprintf(fname, "%s_meta.txt", cs1);

	fp = fopen(fname, "rb");
        if (fp == NULL) {
          fprintf(stderr, "Error: no metadata file %s\n", fname);
          exit(1);
        }
	temp = (char *)malloc(sizeof(char)*(strlen(argv[1])+20));
	if (fscanf(fp, "%s", temp) != 1) {
		fprintf(stderr, "Metadata file - bad format\n");
		exit(0);
	}
	
	if (fscanf(fp, "%d", &origsize) != 1) {
		fprintf(stderr, "Original size is not valid\n");
		exit(0);
	}
	if (fscanf(fp, "%d %d %d %d %d", &k, &m, &w, &packetsize, &buffersize) != 5) {
		fprintf(stderr, "Parameters are not correct\n");
		exit(0);
	}
	c_tech = (char *)malloc(sizeof(char)*(strlen(argv[1])+20));
	if (fscanf(fp, "%s", c_tech) != 1) {
		fprintf(stderr, "Metadata file - bad format\n");
		exit(0);
	}
	if (fscanf(fp, "%d", &tech) != 1) {
		fprintf(stderr, "Metadata file - bad format\n");
		exit(0);
	}
	method = tech;
	if (fscanf(fp, "%d", &readins) != 1) {
		fprintf(stderr, "Metadata file - bad format\n");
		exit(0);
	}
	fclose(fp);	

	/* Allocate memory */
	erased = (int *)malloc(sizeof(int)*(k+m));
	for (i = 0; i < k+m; i++)
		erased[i] = 0;
	erasures = (int *)malloc(sizeof(int)*(k+m));

	data = (char **)malloc(sizeof(char *)*k);
	coding = (char **)malloc(sizeof(char *)*m);
	if (buffersize != origsize) {
		for (i = 0; i < k; i++) {
			data[i] = (char *)malloc(sizeof(char)*(buffersize/k));
		}
		for (i = 0; i < m; i++) {
			coding[i] = (char *)malloc(sizeof(char)*(buffersize/k));
		}
		blocksize = buffersize/k;
	}

	sprintf(temp, "%d", k);
	md = strlen(temp);

	/* Create coding matrix or bitmatrix */
	matrix = reed_sol_vandermonde_coding_matrix(k, m, w);
	
	/* Begin decoding process */
	total = 0;
	n = 1;	
	while (n <= readins) {
		numerased = 0;
		/* Open files, check for erasures, read in data/coding */	
		for (i = 1; i <= k; i++) {
			sprintf(fname, "%s_k%0*d%s", cs1, md, i, extension);
			fp = fopen(fname, "rb");
			if (fp == NULL) {
				erased[i-1] = 1;
				erasures[numerased] = i-1;
				numerased++;
				//printf("%s failed\n", fname);
			}
			else {
				if (buffersize == origsize) {
					stat(fname, &status);
					blocksize = status.st_size;
					data[i-1] = (char *)malloc(sizeof(char)*blocksize);
					assert(blocksize == fread(data[i-1], sizeof(char), blocksize, fp));
				}
				else {
					fseek(fp, blocksize*(n-1), SEEK_SET); 
					assert(buffersize/k == fread(data[i-1], sizeof(char), buffersize/k, fp));
				}
				fclose(fp);
			}
		}
		for (i = 1; i <= m; i++) {
			sprintf(fname, "%s_m%0*d%s", cs1, md, i, extension);
				fp = fopen(fname, "rb");
			if (fp == NULL) {
				erased[k+(i-1)] = 1;
				erasures[numerased] = k+i-1;
				numerased++;
				//printf("%s failed\n", fname);
			}
			else {
				if (buffersize == origsize) {
					stat(fname, &status);
					blocksize = status.st_size;
					coding[i-1] = (char *)malloc(sizeof(char)*blocksize);
					assert(blocksize == fread(coding[i-1], sizeof(char), blocksize, fp));
				}
				else {
					fseek(fp, blocksize*(n-1), SEEK_SET);
					assert(blocksize == fread(coding[i-1], sizeof(char), blocksize, fp));
				}	
				fclose(fp);
			}
		}
		/* Finish allocating data/coding if needed */
		if (n == 1) {
			for (i = 0; i < numerased; i++) {
				if (erasures[i] < k) {
					data[erasures[i]] = (char *)malloc(sizeof(char)*blocksize);
				}
				else {
					coding[erasures[i]-k] = (char *)malloc(sizeof(char)*blocksize);
				}
			}
		}
		
		erasures[numerased] = -1;
	
		/* Choose proper decoding method */
		i = jerasure_matrix_decode(k, m, w, matrix, 1, erasures, data, coding, blocksize);
	
		/* Exit if decoding was unsuccessful */
		if (i == -1) {
			fprintf(stderr, "Unsuccessful!\n");
			exit(0);
		}
	
		/* Create decoded file */
		sprintf(fname, "%s_decoded%s", cs1, extension);
		if (n == 1) {
			fp = fopen(fname, "wb");
		}
		else {
			fp = fopen(fname, "ab");
		}
		for (i = 0; i < k; i++) {
			if (total+blocksize <= origsize) {
				fwrite(data[i], sizeof(char), blocksize, fp);
				total+= blocksize;
			}
			else {
				for (j = 0; j < blocksize; j++) {
					if (total < origsize) {
						fprintf(fp, "%c", data[i][j]);
						total++;
					}
					else {
						break;
					}
					
				}
			}
		}
		n++;
		fclose(fp);
	}
	
	/* Free allocated memory */
	free(cs1);
	free(extension);
	free(fname);
	free(data);
	free(coding);
	free(erasures);
	free(erased);
	
	printf("File has been decoded!\n");

	return 0;
}	

