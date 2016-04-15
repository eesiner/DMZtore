#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/bio.h> 
#include <openssl/rsa.h> 
#include <openssl/pem.h> 
#include <openssl/err.h> 
#include <dirent.h>

//Authentication function
int authenticate(unsigned char* auth_token, char* auth_ts, char* ip) {
	//reads in local AT and public key. Verify against AT sent by client
	RSA *public_key; 
    	FILE* pub = fopen("public.pem", "rb");
        public_key = PEM_read_RSAPublicKey(pub, NULL, NULL, NULL); 

   	if(public_key == NULL) { 
      		ERR_print_errors_fp(stdout); 
		return 0;
   	} 

	char ip_add[40];
	memcpy (ip_add, ip, 40);
	char hashedinput[1024];
	char hashedfilename[64];
	sprintf(hashedfilename, "AT%s.data", ip_add);
	FILE* hashedfile = fopen(hashedfilename, "r");
    	fseek(hashedfile, 0L, SEEK_END);
    	int fsize3 = ftell(hashedfile);
    	//set back to normal
    	fseek(hashedfile, 0L, SEEK_SET);
    	fread(hashedinput,sizeof(char),fsize3, hashedfile);
	fclose(hashedfile);
	strcat(hashedinput, auth_ts);
	int verify = 0;
	//returns 1 if verify successful; else 0.
        verify = RSA_verify(NID_sha1, (unsigned char*) hashedinput, strlen(hashedinput), auth_token, 256, public_key);
	memset(hashedinput, 0, sizeof(hashedinput)); 
	return verify;
}

//function gets IP address of server
void getIPAddress(char* IP)
{
    	int fd;
 	struct ifreq ifr;

 	fd = socket(AF_INET, SOCK_DGRAM, 0);

 	/* get IP address of a specified interface */
 	ifr.ifr_addr.sa_family = AF_INET;

	//change the adapter name accordingly.
 	//strncpy(ifr.ifr_name, "egiga0", IFNAMSIZ-1); 
 	strncpy(ifr.ifr_name, "lo", IFNAMSIZ-1); 

 	ioctl(fd, SIOCGIFADDR, &ifr);

 	close(fd);

 	/* save ip address */
 	sprintf(IP, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	return;
 
}


//main function
int main(int argc, char *argv[]){
	if(argc != 2) {
		printf("Usage: ./server.exe <port>");
		return 1;
	}

	//create sockets
	int welcomeSocket, newSocket;
	unsigned char buffer[20480];
	struct sockaddr_in serverAddr;
	struct sockaddr_storage serverStorage;
	socklen_t addr_size;
	int data = 0;
	fflush(stdin);
	welcomeSocket = socket(AF_INET, SOCK_STREAM, 0);
		if(welcomeSocket == -1) {
			printf("Socket error\n");
			exit(1);
		}
	
	int port = 0;
	char portstr[6] = "";
	strncpy(portstr, argv[1], 5);
	port = atoi(portstr);
	char ipaddressofserver[40] = "";
	getIPAddress(ipaddressofserver);
	printf("Created socket on %s\n", ipaddressofserver);
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(port);
	serverAddr.sin_addr.s_addr = inet_addr(ipaddressofserver);\
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

	//binding a listening socket on the server
	if(bind(welcomeSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) == -1) {
		int reuse;
		setsockopt(welcomeSocket, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(int));
		bind(welcomeSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));
	}
	while(1){
		//listen for incoming connections
	  	if(listen(welcomeSocket,1)==0)
	    		printf("Listening for connection...\n");
	  	else
	    	printf("Error\n");
	  	addr_size = sizeof serverStorage;

  	  	newSocket = accept(welcomeSocket, (struct sockaddr *) &serverStorage, &addr_size);
	  	printf("New connection!\n");

		while(1) {
			printf("Waiting...\n");
		  	fflush(stdin);
			memset(buffer, 0, sizeof(buffer)); 
		  	recv(newSocket, buffer, 20480, 0); //wait for request from client
		  	fflush(stdin);
			printf("Received %s request...\n", buffer);

			if(strcmp(buffer, "upload") == 0) { //upload request
				send(newSocket,"1\0",64,0);
				printf("upload\n");
				unsigned char auth_token[2048] = "";
				recv(newSocket, auth_token, 2048, 0);
				auth_token[strlen(auth_token)] = '\0';
				unsigned char auth_ts[20] = "";
				recv(newSocket, auth_ts, 20, 0);
				auth_ts[strlen(auth_ts)] = '\0';
				char ip_add[40] = "";
				sprintf(ip_add, "%s:%s", ipaddressofserver, portstr);
				int auth = authenticate(auth_token, auth_ts, ip_add);
				if(auth == 1) {
					send(newSocket,"1\0",64,0);
					printf("Authentication Success\n");
				} else {
					send(newSocket,"0\0",64,0);
					printf("Authentication Failure\n");
					continue;
				}

				char counter[5];
			 	 recv(newSocket, counter, 5, 0);
				int count = atoi(counter);

				while(count > 0) {
					char filename[64];
				 	 recv(newSocket, filename, 64, 0);
	
					char filesize[10];
					int fsize = 0;
			
				  	recv(newSocket, filesize, 10, 0);
					fsize = atoi(filesize);
	
				  	recv(newSocket, buffer, 20480, 0);
					  fflush(stdin);
				  	
					FILE *fOUT;
					fOUT = fopen(filename, "wb");
				   	 fwrite(buffer,sizeof(char),fsize,fOUT);
					fclose(fOUT);		  
					printf("Received file (%s)\n", filename);
					send(newSocket,"1\0",3,0);
					count--;
				}
				memset(buffer, 0, sizeof(buffer)); 
				memset(auth_ts, 0, sizeof(auth_ts)); 
				memset(auth_token, 0, sizeof(auth_token)); 
			  	fflush(stdin);
			} else if(strcmp(buffer, "download") == 0) { //download
				send(newSocket,"1\0",64,0);
				printf("download\n");
				unsigned char auth_token[2048] = "";
				recv(newSocket, auth_token, 2048, 0);
				auth_token[strlen(auth_token)] = '\0';
				unsigned char auth_ts[20] = "";
				recv(newSocket, auth_ts, 20, 0);
				auth_ts[strlen(auth_ts)] = '\0';
				char ip_add[40] = "";
				sprintf(ip_add, "%s:%s", ipaddressofserver, portstr);
				int auth = authenticate(auth_token, auth_ts, ip_add);
				if(auth == 1) {
					send(newSocket,"1\0",64,0);
					printf("Authentication Success\n");
				} else {
					send(newSocket,"0\0",64,0);
					printf("Authentication Failure\n");
					continue;
				}

				char counter[5];
				recv(newSocket, counter, 5, 0);
				int count = atoi(counter);
	
				while(count > 0) {
					char filename[64];
				 	recv(newSocket, filename, 64, 0);
					fflush(stdin);
					printf("Download request for %s received.\n", 	filename);
				 	FILE* fin = fopen(filename, "rb");
					fseek(fin, 0L, SEEK_END);
					int fsize = ftell(fin);
					fseek(fin, 0L, SEEK_SET);
			    		unsigned char *indata = malloc(fsize);
			    		fread(indata,sizeof(char),fsize, fin);
	
					char sendsize[10];
					sprintf(sendsize, "%d", fsize);
					send(newSocket,sendsize,10,0);
	
					send(newSocket,indata,fsize,0);

					char confirmation[3];
			  		recv(newSocket, confirmation, 3, 0);
					if(strcmp(confirmation, "1") == 0) {
						printf("File %s has been sent!\n", filename);
					} else {
						printf("Error occured when sending %s...\n", filename);
					}
		    			fclose(fin);
					count--;
				}
				memset(buffer, 0, sizeof(buffer)); 
				memset(auth_ts, 0, sizeof(auth_ts)); 
				memset(auth_token, 0, sizeof(auth_token)); 
			 	fflush(stdin);
			} else if(strcmp(buffer, "update") == 0) { //update AT and public key request
				send(newSocket,"1\0",64,0);
				printf("update\n");
				unsigned char password[1024] = "";
				memset(password, 0, sizeof(password)); 
				recv(newSocket, password, 1024, 0);
				if(strcmp(password, "secondpassword") == 0) {
					send(newSocket,"1\0",64,0);
					printf("Authentication Success\n");
				} else {
					send(newSocket,"0\0",64,0);
					printf("Authentication Failure\n");
					continue;
				}


				printf("Updating AT and Public Key... ");
				int count = 2;
				while(count > 0) {
					char filename[64];

				 	 recv(newSocket, filename, 64, 0);
	
					char filesize[10];
					int fsize = 0;
			
				  	recv(newSocket, filesize, 10, 0);
					fsize = atoi(filesize);
	
				  	recv(newSocket, buffer, 20480, 0);
					  fflush(stdin);
				  	
					FILE *fOUT;
					fOUT = fopen(filename, "wb");
				   	 fwrite(buffer,sizeof(char),fsize,fOUT);
					fclose(fOUT);		  
					send(newSocket,"1\0",3,0);
					count--;
				}
				printf("DONE\n");
				memset(buffer, 0, sizeof(buffer)); 
				fflush(stdin);
			} else if(strcmp(buffer, "retrieve") == 0) { //client request for files available for download
				printf("Sending file listings... ");
				char allfiles[2048] = "";

				DIR *dp = NULL;
				struct dirent *ep = NULL;
				int count = 0;

				dp = opendir ("./");
				if (dp != NULL) {
					while (ep = readdir (dp)) {
						char *extension = strrchr(ep->d_name, '.');
						if(!(strcmp(extension, ".data") == 0 || strcmp(extension, ".pem") == 0 || strcmp(extension, ".") == 0 || strcmp(extension, "..") == 0 || strcmp(ep->d_name, "server_arm.exe") == 0 || strcmp(ep->d_name, "server.exe") == 0)) {
							if(count > 0) {
								strcat(allfiles, ",");
							}
							strcat(allfiles, ep->d_name);
							count++;
						}
					}
					(void) closedir (dp);
				} else {
					printf("nothing's coming");
				}
				send(newSocket,allfiles,2048,0);
				printf("OK\n");
				strcpy(allfiles, "");
				memset(buffer, 0, sizeof(buffer)); 
				fflush(stdin);
			} else if(strcmp(buffer, "disconnect") == 0) { //client disconnects
				printf("Client disconnected.\n");
				close(newSocket); //close listening socket and return to listen for new connections
				break;
			} else {
				printf("Invalid\n");
				continue;
			}
		}
		memset(buffer, 0, sizeof(buffer)); 
		fflush(stdin);
	}
	close(welcomeSocket);
	return 0;
}


