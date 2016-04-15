#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>

void authenticate(unsigned char* atinput, char* ip_add) {
	char atfilename[64];
	sprintf(atfilename, "AT%s.data", ip_add);
    FILE* atfile = fopen(atfilename, "r");
    fseek(atfile, 0L, SEEK_END);
    int fsize = ftell(atfile);
    //set back to normal
    fseek(atfile, 0L, SEEK_SET);
    fread(atinput,sizeof(char),fsize, atfile);
	fclose(atfile);

	char attimestamp[64];
	char timestamp[20];
	sprintf(attimestamp, "AT%s.data.timestamp", ip_add);
	FILE* tsfile = fopen(attimestamp, "r");
    fseek(tsfile, 0L, SEEK_END);
    int fsize2 = ftell(tsfile);
    //set back to normal
    fseek(tsfile, 0L, SEEK_SET);
    fread(timestamp,sizeof(char),fsize2, tsfile);
	timestamp[10] = '\0';
	fclose(tsfile);
	strcat(atinput, timestamp);
}

int main(int argc, char *argv[]){
	
	if(argc == 1) {
		printf("usage: [--upload|--download] serverIP <files>\n");
		printf("OR\nusage: --update serverIP password\n");
		exit(1);
	}
	if(!(strcmp(argv[1], "--upload") == 0 || strcmp(argv[1], "--download") == 0 || strcmp(argv[1], "--update") == 0)) {
		printf("usage: [--upload|--download] serverIP <files>\n");
		printf("OR\nusage: --update serverIP password\n");
		exit(1);
	}
	if(strcmp(argv[1], "--update") != 0 && argc < 4) {
		printf("usage: [--upload|--download] serverIP <files>\n");
		printf("OR\nusage: --update serverIP password\n");
		exit(1);
	}
	if(strcmp(argv[1], "--update") == 0 && argc != 4) {
		printf("usage: [--upload|--download] serverIP <files>\n");
		printf("OR\nusage: --update serverIP password\n");
		exit(1);
	}

	  int clientSocket;
	  unsigned char buffer[20480];
	  struct sockaddr_in serverAddr;
	  socklen_t addr_size;
	
	  clientSocket = socket(PF_INET, SOCK_STREAM, 0);
	  
	  serverAddr.sin_family = AF_INET;
	  serverAddr.sin_port = htons(9999);
	  serverAddr.sin_addr.s_addr = inet_addr(argv[2]);
	  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  
	
	  addr_size = sizeof serverAddr;
		printf("Connecting to %s... ", argv[2]);
	  if(connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size) == 0) {
	printf("CONNECTED\n");
	} else {
	printf("FAILED\n");
	exit(1);
	}

	char indicator[32];
	strcpy(indicator,argv[1]);
	indicator[strlen(indicator)] = '\0';
	send(clientSocket,indicator,32,0);
	printf("Sent %s request to %s... ", indicator, argv[2]);

	  recv(clientSocket, buffer, 20480, 0);
	  fflush(stdin);
	if(strcmp(buffer, "1") == 0) {
		printf("ACCEPTED\n");
	} else {
		printf("REJECTED\n");
		exit(1);
	}
	//memset(tmp, 0, sizeof(tmp));
	memset(buffer, 0, sizeof(buffer));  

	if(strcmp(argv[1], "--upload") == 0) {
		unsigned char atinput[1024];
		char ip_add[16];
		memcpy (ip_add, argv[2], 16);
		authenticate(atinput, ip_add); 
		send(clientSocket,atinput,1024,0);
		  recv(clientSocket, buffer, 20480, 0);
		if(strcmp(buffer, "1") == 0) {
			printf("Authentication Success\n");
	 	} else {
			printf("Authentication Failure\n");
			exit(1);
		}

		int filecount = argc - 3;
		int index = 3;
		char sendfilecount[3];
		sprintf(sendfilecount, "%d", filecount);
		send(clientSocket,sendfilecount,3,0);
		
		while(index < argc) {
			char uploadname[64];
			strcpy(uploadname, argv[index]);
			uploadname[strlen(uploadname)] = '\0';	
			send(clientSocket,uploadname,64,0);
	
			FILE *fp;
			long lSize;
			fp = fopen ( argv[index] , "rb" );
			fseek(fp, 0L, SEEK_END);
			int fsize = ftell(fp);
			fseek(fp, 0L, SEEK_SET);
	    		unsigned char *indata = malloc(fsize);
	   		fread(indata,sizeof(char),fsize, fp);
			fclose(fp);

			char sendsize[10];
			sprintf(sendsize, "%d", fsize);
			send(clientSocket,sendsize,10,0);
	
			send(clientSocket,indata,fsize,0);
			
			char confirmation[3];
	  		recv(clientSocket, confirmation, 3, 0);
			if(strcmp(confirmation, "1") == 0) {
				printf("File %s has been sent!\n", uploadname);
			} else {
				printf("Error occured when sending %s...\n", uploadname);
			}
			index++;
			fflush(stdin);
		}
	} else if(strcmp(argv[1], "--download") == 0) {
		unsigned char atinput[1024];
		char ip_add[16];
		memcpy (ip_add, argv[2], 16);
		authenticate(atinput, ip_add); 
		send(clientSocket,atinput,1024,0);
		  recv(clientSocket, buffer, 20480, 0);
		if(strcmp(buffer, "1") == 0) {
			printf("Authentication Success\n");
	 	} else {
			printf("Authentication Failure\n");
			exit(1);
		}

		int filecount = argc - 3;
		int index = 3;
		char sendfilecount[5];
		sprintf(sendfilecount, "%d", filecount);
		send(clientSocket,sendfilecount,5,0);

		while(index < argc) {
			char tmpf[64];
			strcpy(tmpf, argv[index]);
			tmpf[strlen(tmpf)] = '\0';
			send(clientSocket,tmpf,64,0);
			printf("Download request for %s sent.\n", tmpf);
		
			char filesize[10];
			int fsize = 0;
			
		  	recv(clientSocket, filesize, 10, 0);
			fsize = atoi(filesize);

			recv(clientSocket, buffer, 20480, 0);
			fflush(stdin);
	   	 	FILE* download = fopen(tmpf, "wb");
	   	 	fwrite(buffer,sizeof(char),fsize,download);
			printf("File has been downloaded (%s)\n", tmpf);
			send(clientSocket,"1\0",3,0);			
			fclose(download);
			index++;
			fflush(stdin);
		}
	} else if(strcmp(argv[1], "--update") == 0) {
		char password[32];
		sprintf(password, "%s", argv[3]);
		send(clientSocket,password,32,0);
		  recv(clientSocket, buffer, 20480, 0);
		if(strcmp(buffer, "1") == 0) {
			printf("Authentication Success\n");
	 	} else {
			printf("Authentication Failure\n");
			exit(1);
		}


		char atfilename[64];
		char pkfilename[64] = "public.pem";
		sprintf(atfilename, "AT%s.data.signed", argv[2]);
	
			FILE *fp;
			long lSize;

			send(clientSocket,atfilename,64,0);
			fp = fopen ( atfilename , "rb" );
			fseek(fp, 0L, SEEK_END);
			int fsize = ftell(fp);
			fseek(fp, 0L, SEEK_SET);
	    		unsigned char *indata = malloc(fsize);
	   		fread(indata,sizeof(char),fsize, fp);
			fclose(fp);

			char sendsize[10];
			sprintf(sendsize, "%d", fsize);
			send(clientSocket,sendsize,10,0);
	
			send(clientSocket,indata,fsize,0);
			
			char confirmation[3];
	  		recv(clientSocket, confirmation, 3, 0);
			if(strcmp(confirmation, "1") == 0) {
				printf("File %s has been sent!\n", atfilename);
			} else {
				printf("Error occured when sending %s...\n", atfilename);
				exit(1);
			}

			send(clientSocket,pkfilename,64,0);
			fp = fopen ( pkfilename , "rb" );
			fseek(fp, 0L, SEEK_END);
			fsize = ftell(fp);
			fseek(fp, 0L, SEEK_SET);
	    		unsigned char *indata2 = malloc(fsize);
	   		fread(indata2,sizeof(char),fsize, fp);
			fclose(fp);

			char sendsize2[10];
			sprintf(sendsize2, "%d", fsize);
			send(clientSocket,sendsize2,10,0);
	
			send(clientSocket,indata2,fsize,0);
			
			char confirmation2[3];
	  		recv(clientSocket, confirmation2, 3, 0);
			if(strcmp(confirmation2, "1") == 0) {
				printf("public.pem has been sent!\n");
			} else {
				printf("Error occured when sending public.pem\n");
				exit(1);
			}
			fflush(stdin);
	}
	
	close(clientSocket);
	  fflush(stdin);
	  return 0;
}
