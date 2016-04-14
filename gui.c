#include <gtk/gtk.h>
#include <ctype.h>
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
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <gf_rand.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "jerasure.h"
#include "reed_sol.h"
#define MAXLEN 40
#define N 10

enum Coding_Technique {Reed_Sol_Van};
char *strcpy();
void updateMessages(char* newMessage);
void updateMessage(char* message);
int checkFileExist(char* file);
int download(GtkWidget* widget, gpointer window, char* action);
void decrypt(char* infile);
void derialize(char* file);
void addToList(uint16_t arrayLen, char *buffer);
void SPtoAT();
void AT(char* sk, char* salt, char* IP, char* Mode);

//structure for serializing of secretpackage
typedef struct item { 
  uint16_t arrayLen;   
  char array[2048];
  struct item *next;
} list;


/* Global variables for signal handler */
unsigned char password1[32];
unsigned char password2[32];
char *Methods[N] = {"reed_sol_van"};
int readins, n;
enum Coding_Technique method;
char tmpfilesarray[100][100];
char tmpwholeip[200];

int clientSocket;
struct sockaddr_in serverAddr;
socklen_t addr_size;

PangoFontDescription *myfont;
GtkWidget *window, *frame; //main gui
GtkWidget *gm0, *gm1, *gm2, *gm3, *gm4, *gm5, *gm6, *gm7, *gm8, *gm9;
GtkWidget *label1, *entry1; //file
GtkWidget *label2, *entry2_0, *entry2_1, *entry2_2; //encode options
GtkWidget *label3, *entry3; //ip
GtkWidget *label4, *entry4; //password
GtkWidget *connectb, *lconnectb;
GtkWidget *disconnectb, *ldisconnectb;
GtkWidget *uploadb, *luploadb;
GtkWidget *downloadb, *ldownloadb;
GtkWidget *updateb, *lupdateb;
GtkWidget *choosespb, *lchoosespb;
GtkWidget *autob, *lautob;
GtkWidget *qb, *lqb;
GtkWidget *meta_entry, *download_entry, *auto_entry, *sp_entry;
GtkWidget *selectfile, *selectfileframe;
list *start = 0;
list *end = 0;

//the following few functions is for demo purposes
void d0() {
	gtk_entry_set_text((GtkEntry*)entry3, "127.0.0.1:10000,127.0.0.1:10001,127.0.0.1:10002");
}

void d1() {
	gtk_entry_set_text((GtkEntry*)entry3, "127.0.0.1:10000");
}

void d2() {
	gtk_entry_set_text((GtkEntry*)entry3, "127.0.0.1:10001");
}

void d3() {
	gtk_entry_set_text((GtkEntry*)entry3, "127.0.0.1:10002");
}

void showDecodedFile() {
	system("gedit test_decoded.txt &");
}

//function to connect to server
//require - only one IP address in the form 'xxx.xxx.xxx.xxx:xxxx'
//result - connects to the server at xxx.xxx.xxx.xxx on port xxxx
int connectTo(GtkWidget *widget, char* action) {
	char ipaddress[40] = "";
	int port = 0;
	char endmessage[50] = "";
	if(strcmp(action, "c") == 0) {
		strcpy(ipaddress, (char*) gtk_entry_get_text((GtkEntry*)entry3));
	} else {
		strcpy(ipaddress, action);
	}
	if(strlen(ipaddress) == 0) {
		updateMessages("IP cannot be empty.");
		return 1;
	}
	if(strchr(ipaddress, ',') != NULL) {
		updateMessages("Please specify only one IP address");
		return 1;
	}
	
	//break ip address specified into ip/port
	char *ip = strtok(ipaddress, ":");
	char *portstr = strtok(NULL, ":");
	port = atoi(portstr);

	clientSocket = socket(PF_INET, SOCK_STREAM, 0);
	  
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(port);
	serverAddr.sin_addr.s_addr = inet_addr(ip);
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  
	
	addr_size = sizeof serverAddr;
		sprintf(endmessage, "Connecting to %s:%s... ", ip, portstr);
		updateMessages(endmessage);
	if(connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size) == 0) {
		updateMessage("CONNECTED");
		gtk_widget_set_sensitive(entry3, FALSE);
		gtk_widget_hide(connectb);
		gtk_widget_show(disconnectb);
		gtk_widget_set_sensitive(uploadb, TRUE);
		gtk_widget_set_sensitive(updateb, TRUE);
		gtk_widget_set_sensitive(downloadb, TRUE);
		gtk_widget_set_sensitive(qb, FALSE);
	} else {
		updateMessage("FAILED");
		return 1;
	}
}

//disconnect from server
//require - client to be connected to a server
//result - disconnected from server
void disconnectFrom(GtkWidget *widget, char* action) {
	char endmessage[50];
	char indicator[20] = "disconnect";
	updateMessages("Disconnecting from ");
	if(strcmp(action, "d") == 0) {
		updateMessage((char*) gtk_entry_get_text((GtkEntry*) entry3));
	} else {
		updateMessage(action);
	}
	updateMessage("... ");
	send(clientSocket,indicator,20,0);
	close(clientSocket);
	updateMessage("DISCONNECTED");
	gtk_widget_set_sensitive(entry3, TRUE);
	gtk_widget_set_sensitive(uploadb, FALSE);
	gtk_widget_set_sensitive(updateb, FALSE);
	gtk_widget_set_sensitive(downloadb, FALSE);
	gtk_widget_hide(disconnectb);
	gtk_widget_show(connectb);
	gtk_widget_set_sensitive(qb, TRUE);
}

//function prepares signed AT and timestamp for authentication with svr
//require - AT.data.signed and AT.data.timestamp to be in cwd
//result - signed AT and timestamp returned to calling function
void authenticate(unsigned char* atinput, char* auth_ts, char* ip_add) {
	char atfilename[64];
	sprintf(atfilename, "AT%s.data.signed", ip_add);
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
	fread(auth_ts,sizeof(char),fsize2, tsfile);
	auth_ts[10] = '\0';
	fclose(tsfile);
}

//initialize and display the file chooser GUI
//some tweaks to the GUI according to the calling function
int browseFile(GtkWidget *widget, gpointer window, char* action) {
	char dialogmsg[30];
	if(strcmp(action, "upload") == 0) {
		strcpy(dialogmsg, "Select file(s)");
	} else {
		strcpy(dialogmsg, "Select a file");
	}
	GtkWidget* dialog;
	if(strcmp(action, "save") == 0) {
		dialog = gtk_file_chooser_dialog_new ("Save SP", GTK_WINDOW(window), GTK_FILE_CHOOSER_ACTION_SAVE, GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT, NULL);
		gtk_file_chooser_set_do_overwrite_confirmation (GTK_FILE_CHOOSER (dialog), TRUE);
		gint resp = gtk_dialog_run(GTK_DIALOG(dialog));
		if(resp==GTK_RESPONSE_ACCEPT) {
			char command[150] = "";
    			char *filename = (char*) gtk_file_chooser_get_filename(GTK_FILE_CHOOSER (dialog));
			sprintf(command, "cp secretpackage.data.encrypted %s", filename);
			system(command);
			updateMessages("SP saved to ");
			updateMessage(filename);
			gtk_widget_destroy(dialog);
			return 0;
		} else {
			gtk_widget_destroy(dialog);
			return 1;
		}
	} else {
		dialog = gtk_file_chooser_dialog_new(dialogmsg, GTK_WINDOW(window),GTK_FILE_CHOOSER_ACTION_OPEN, GTK_STOCK_OK, GTK_RESPONSE_OK, GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, NULL);
		if(strcmp(action, "upload") == 0) {
			gtk_file_chooser_set_select_multiple(GTK_FILE_CHOOSER(dialog), TRUE);
		} else { 
			gtk_file_chooser_set_select_multiple(GTK_FILE_CHOOSER(dialog), FALSE);
		}
	}
	gtk_widget_show_all(dialog);
	gint resp = gtk_dialog_run(GTK_DIALOG(dialog));
	if(resp==GTK_RESPONSE_OK) {
		if(strcmp(action, "meta") == 0) {
			gtk_entry_set_text((GtkEntry*)meta_entry, gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog)));
			updateMessages("Meta file selected.");
		} else if(strcmp(action, "upload") == 0) {
			gtk_entry_set_text((GtkEntry*)entry1, "");
			gtk_entry_set_text((GtkEntry*)meta_entry, "");
			GSList *selected_filenames = gtk_file_chooser_get_filenames(GTK_FILE_CHOOSER(dialog));
			guint noFiles = g_slist_length(selected_filenames);
			int i = 0;
			for(i = 0; i < noFiles; i++) {
				gtk_entry_append_text((GtkEntry*)entry1, g_slist_nth_data(selected_filenames, i));
				if(i < noFiles - 1) {
					gtk_entry_append_text((GtkEntry*)entry1, ",");
				}
			}
		} else if(strcmp(action, "SP") == 0) {
			gtk_entry_set_text((GtkEntry*)sp_entry, gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog)));
		} else {
			gtk_entry_set_text((GtkEntry*)entry1, gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog)));
			gtk_entry_set_text((GtkEntry*)meta_entry, "");
		} 
	} else {
		gtk_entry_set_text((GtkEntry*)meta_entry, "");
		gtk_widget_destroy(dialog);
		return 1;
	}
	gtk_widget_destroy(dialog);
	return 0;
}

//sends file(s) to server
//require - client connected to svr, matching signed AT and timestamp.
//result - selected files are uploaded to server if auth successful.
int upload(GtkWidget *widget, char* action) {
	if(strlen(action) == 0) {
		browseFile(NULL, NULL, "upload");
	}
	if(strlen(gtk_entry_get_text((GtkEntry*)entry1)) == 0) {
		return 1;
	}
	char *allfiles = (char*)gtk_entry_get_text((GtkEntry*)entry1);
	int noFiles = 1;
	int i = 0;
	for(i = 0; i < strlen(allfiles); i++) {
		if(allfiles[i] == ',') {
			noFiles++;
		}
	}
	char endmessage[50];
	char* ip_add;
	char encryptedfile[100] = "";
	if(strlen(action) == 0) {
		ip_add = (char*)gtk_entry_get_text((GtkEntry*)entry3);
	} else {
		ip_add = action;
		noFiles = 1;
		int z = 0;
		for(int z = 0; z < 100; z++) {
			if(strlen(tmpfilesarray[z]) != 0) {
				strcpy(encryptedfile, tmpfilesarray[z]);
				strcpy(tmpfilesarray[z], "");
				allfiles = encryptedfile;
				break;
			}
		}
	}
	char *filesarray[noFiles];
	char *each;
	i = 0;
	each = strtok(allfiles,",");
	while(each != NULL) {
		filesarray[i++] = each;
		each = strtok(NULL, ",");
	}

	unsigned char buffer[20480];
	char indicator[10] = "upload";
	send(clientSocket,indicator,10,0);
	sprintf(endmessage, "Sent upload request to %s... ", ip_add);
	updateMessages(endmessage);
	recv(clientSocket, buffer, 20480, 0);
	fflush(stdin);
	if(strcmp(buffer, "1") == 0) {
		updateMessage("ACCEPTED");
	} else {
		updateMessage("REJECTED");
		return 1;
	}
	unsigned char atinput[2048] = "";
	char auth_ts[20] = "";
	authenticate(atinput, auth_ts, ip_add);
	send(clientSocket,atinput,2048,0);
	send(clientSocket,auth_ts,20,0);
	recv(clientSocket, buffer, 20480, 0);
	if(strcmp(buffer, "1") == 0) {
		updateMessages("Authentication Success");
	} else {
		updateMessages("Authentication Failure");
		return 1;
	}
	int filecount = noFiles;
	int index = 0;
	char sendfilecount[3];
	sprintf(sendfilecount, "%d", filecount);
	send(clientSocket,sendfilecount,3,0);
	
	while(index < noFiles) {
		char uploadname[128] = "";
		strcpy(uploadname, filesarray[index]);
		if(strlen(action) == 0) {
			strcpy(uploadname,strrchr(uploadname, '/'));
			int tmpi = 0;
			for(tmpi = 0; tmpi < strlen(uploadname) - 1; tmpi++) {
				uploadname[tmpi] = uploadname[tmpi + 1];
			}
			uploadname[strlen(uploadname) - 1] = '\0';
		}
		send(clientSocket,uploadname,64,0);
		
		FILE *fp;
		long lSize;
		fp = fopen ( filesarray[index] , "rb" );
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
			updateMessages("File ");
			updateMessage(uploadname);
			updateMessage(" has been sent!");
		} else {
			updateMessages("Error occured when sending ");
			updateMessage(uploadname);
		}	
		index++;
		fflush(stdin);
	}
	memset(buffer, 0, sizeof(buffer)); 
	memset(atinput, 0, sizeof(atinput)); 
	fflush(stdin);
	return 0;
}

//just a function to control the 'downloading' program flow
void buttonclicked(GtkWidget* widget, char* filename) {
	char check[2048];
	strcpy(check, gtk_entry_get_text((GtkEntry*)download_entry));
	if(strlen(check) != 0) {
		gtk_entry_append_text((GtkEntry*)download_entry, ",");
	}
	gtk_entry_append_text((GtkEntry*)download_entry, filename);
	gtk_widget_set_sensitive(widget, FALSE);
	updateMessages("Selected file ");
	updateMessage(filename);
}

//just a function to control the 'downloading' program flow
void okclicked(GtkWidget* widget, gpointer window) {
	gtk_widget_destroy(selectfile);
	download(NULL, NULL, "start");
}	

//just a function to control the 'downloading' program flow
void cancelclicked(GtkWidget* widget, gpointer window) {
	gtk_widget_set_sensitive(downloadb, TRUE);
}

//request for available files for download from server
//require - client connected to svr, matching signed AT and timestamp.
//result - svr respond with list of available files for download.
void showAvailableFiles() {
	char allfiles[2048] = "";
	strcpy(allfiles, (char*)gtk_entry_get_text((GtkEntry*)download_entry));
	gtk_entry_set_text((GtkEntry*)download_entry, "");
	int noFiles = 1;
	int i = 0;
	for(i = 0; i < strlen(allfiles); i++) {
		if(allfiles[i] == ',') {
			noFiles++;
		}
	}
	char *each;
	i = 0;
	each = strtok(allfiles,",");
	while(each != NULL) {
		strcpy(tmpfilesarray[i], each);
		each = strtok(NULL, ",");
		i++;
	}

	GtkWidget *fokb, *lfokb;

	selectfile = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_position(GTK_WINDOW(selectfile), GTK_WIN_POS_CENTER);
	gtk_window_set_title(GTK_WINDOW(selectfile), "Select file(s) to download");
	gtk_window_set_default_size(GTK_WINDOW(selectfile), 300, noFiles * 40 + 40);
	gtk_container_set_border_width(GTK_CONTAINER(selectfile), 10);
	
	selectfileframe = gtk_fixed_new();
	gtk_container_add(GTK_CONTAINER(selectfile), selectfileframe);

	lfokb = gtk_label_new("Download");
	gtk_widget_modify_font(lfokb, myfont);
	fokb = gtk_button_new();
	gtk_container_add(GTK_CONTAINER(fokb), lfokb);

	gtk_fixed_put(GTK_FIXED(selectfileframe), fokb, 4, noFiles * 40 - 5);
	gtk_widget_set_size_request(fokb, (gint) 290, (gint) 40);

	gtk_window_set_transient_for(GTK_WINDOW(selectfile), GTK_WINDOW(window));

	GtkWidget* filesb[noFiles];
	GtkWidget* lfilesb[noFiles];

	for(i = 0; i < noFiles; i++) {
		lfilesb[i] = gtk_label_new(tmpfilesarray[i]);
		gtk_widget_modify_font(lfilesb[i], myfont);
		filesb[i] = gtk_button_new();
		gtk_container_add(GTK_CONTAINER(filesb[i]), lfilesb[i]);
		gtk_fixed_put(GTK_FIXED(selectfileframe), filesb[i], 4, 5 + (35*i));
		gtk_widget_set_size_request(filesb[i], (gint) 290, (gint) 30);
		g_signal_connect(filesb[i], "clicked", G_CALLBACK(buttonclicked), tmpfilesarray[i]);	
	}

	g_signal_connect(fokb, "clicked", G_CALLBACK(okclicked), NULL);
	g_signal_connect(selectfile, "destroy", G_CALLBACK(cancelclicked), NULL);

	gtk_widget_show_all(selectfile);
	return;
}

//begin download of selected available files from the server
//require - client connected to svr, matching signed AT and timestamp
//result - invokes showAvailableFiles() function
//result - client downloads selected files when 'Download' is clicked
int download(GtkWidget *widget, gpointer window, char* action) {
	unsigned char buffer[20480] = "";
	if(strcmp(action, "start") != 0) {
		gtk_widget_set_sensitive(widget, FALSE);
		send(clientSocket,"retrieve\0",10,0);
		char allfiles[2048] = "";
		recv(clientSocket, allfiles, 20480, 0);
		gtk_entry_set_text((GtkEntry*) download_entry, allfiles);
		if(strlen((char*)gtk_entry_get_text((GtkEntry*)download_entry)) == 0) {
			updateMessages("No files available for download");
			gtk_widget_set_sensitive(downloadb, TRUE);
			gtk_entry_set_text((GtkEntry*) download_entry, "");
			strcpy(allfiles, ""); 
			memset(buffer, 0, sizeof(buffer)); 
			return 1;
		} else {
			showAvailableFiles();
			return 1;
		}
	}
	char selectedfiles[2048] = "";
	strcpy(selectedfiles, gtk_entry_get_text((GtkEntry*)download_entry));
	if(strlen(selectedfiles) == 0) {
		updateMessages("Error: No file(s) selected.");
		return 1;
	}
	updateMessages("Downloading files ");
	updateMessage(selectedfiles);
	updateMessage("...");

	char endmessage[50];
	char* ip_add = (char*)gtk_entry_get_text((GtkEntry*)entry3);

	char indicator[10] = "download";
	send(clientSocket,indicator,10,0);
	sprintf(endmessage, "Sent download request to %s... ", ip_add);
	updateMessages(endmessage);
	recv(clientSocket, buffer, 20480, 0);
	fflush(stdin);
	if(strcmp(buffer, "1") == 0) {
		updateMessage("ACCEPTED");
	} else {
		updateMessage("REJECTED");
		return 1;
	}

	unsigned char atinput[2048] = "";
	char auth_ts[20] = "";
	authenticate(atinput, auth_ts, ip_add); 
	send(clientSocket,atinput,2048,0);
	send(clientSocket,auth_ts,20,0);
	recv(clientSocket, buffer, 20480, 0);
	if(strcmp(buffer, "1") == 0) {
		updateMessages("Authentication Success");
 	} else {
		updateMessages("Authentication Failure");
		return 1;
	}

	char getselectedfiles[2048] = "";
	strcpy(getselectedfiles, (char*) gtk_entry_get_text((GtkEntry*)download_entry));

	int noFiles = 1;
	int i = 0;
	for(i = 0; i < strlen(getselectedfiles); i++) {
		if(getselectedfiles[i] == ',') {
			noFiles++;
		}
	}
	char filesarray[noFiles][100];
	char *each;
	i = 0;
	each = strtok(getselectedfiles,",");
	while(each != NULL) {
		strcpy(filesarray[i], each);
		each = strtok(NULL, ",");
		i++;
	}
	int filecount = noFiles;
	int index = 0;
	char sendfilecount[5];
	sprintf(sendfilecount, "%d", filecount);
	send(clientSocket,sendfilecount,5,0);

	while(index < filecount) {
		char tmpf[64] = "";
		strcpy(tmpf, filesarray[index]);
		tmpf[strlen(tmpf)] = '\0';
		send(clientSocket,tmpf,64,0);
		updateMessages("Download request sent for ");
		updateMessage(tmpf);
	
		char filesize[10];
		int fsize = 0;
			
	  	recv(clientSocket, filesize, 10, 0);
		fsize = atoi(filesize);

		recv(clientSocket, buffer, 20480, 0);
		fflush(stdin);
   	 	FILE* download = fopen(tmpf, "wb");
   	 	fwrite(buffer,sizeof(char),fsize,download);
		updateMessages("File has been downloaded (");
		updateMessage(tmpf);
		updateMessage(")");
		send(clientSocket,"1\0",3,0);			
		fclose(download);
		index++;
		fflush(stdin);
	}
	memset(buffer, 0, sizeof(buffer)); 
	memset(atinput, 0, sizeof(atinput)); 
	memset(getselectedfiles, 0, sizeof(getselectedfiles));
	memset(filesarray, 0, sizeof(filesarray)); 
	gtk_entry_set_text((GtkEntry*) download_entry, "");
	fflush(stdin);
	return 0;
}

//updates AT on the server
//require - client to be connected to svr.
//result - client updates AT.data and public.pem on svr.
void updateSvrAT(GtkWidget *widget, char* action) {
	char* IP;
	if(strlen(action) == 0) {
		IP = (char*)gtk_entry_get_text((GtkEntry*)entry3);
	} else {
		IP = action;
	}
	int exist = 0;
	char atfilename[64];
	char pkfilename[64] = "public.pem";
	sprintf(atfilename, "AT%s.data", IP);
	exist = checkFileExist(atfilename);
	if(exist != 1) {
		updateMessages(atfilename);
		updateMessage(" does not exist.");
		return;
	}
	exist = 0;
	exist = checkFileExist(pkfilename);
	if(exist != 1) {
		updateMessages(pkfilename);
		updateMessage(" does not exist.");
		return;
	}

	unsigned char buffer[20480];
	char endmessage[50];
	char indicator[10] = "update";
	send(clientSocket,indicator,10,0);
	sprintf(endmessage, "Sent update request to %s... ", IP);
	updateMessages(endmessage);

	recv(clientSocket, buffer, 20480, 0);
	fflush(stdin);
	if(strcmp(buffer, "1") == 0) {
		updateMessage("ACCEPTED");
	} else {
		updateMessage("REJECTED");
		return;
	}
	//memset(tmp, 0, sizeof(tmp));
	memset(buffer, 0, sizeof(buffer)); 

	char password[32] = "";
	sprintf(password, "%s", "secondpassword");
	send(clientSocket,password,32,0);
	recv(clientSocket, buffer, 20480, 0);
	if(strcmp(buffer, "1") == 0) {
		updateMessages("Authentication Success");
	} else {
		updateMessages("Authentication Failure");
		return;
	}

	sprintf(endmessage, "Sending file %s... ", atfilename);
	updateMessages(endmessage);
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
		updateMessage("OK");
	} else {
		updateMessage("FAILED");
		return;
	}
	updateMessages("Sending public.pem... ");
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
		updateMessage("OK");
	} else {
		updateMessages("Error occured when sending public.pem");
		return;
	}
	updateMessages("Successfully updated AT!");
	fflush(stdin);
}

//manually choose a secretpackage file, derialize it and create an AT
//require - a secretpackage file from an external source.
//result - upon loading of SP, corresponding ATs and signed ATs will
//result - will be created with a timestamp. A Metafile describing the
//result - original file encoded by erasure coding will also be created.
void chooseSP() {
	char secretkey[2048] = "";
	char salt[2048] = "";
	char IP[2048] = "";
	if(strlen((char*)gtk_entry_get_text((GtkEntry*)entry4)) == 0) {
		updateMessages("Password must be specified.");
		return;
	}
	char action[5] = "SP";
	int error = browseFile(NULL, NULL, action);
	if(error == 1) {
		return;
	}
	updateMessages("Secretpackage manually selected.");
	char* spfilename = (char*)gtk_entry_get_text((GtkEntry*)sp_entry);
	char command[100] = "";
	snprintf(command, 99, "cp %s ./secretpackage.data.encrypted", spfilename);
	system(command);
	decrypt("secretpackage.data.encrypted");
	system("mv secretpackage.data.decrypted secretpackage.data");
	system("rm secretpackage.data.decrypted");
	derialize("secretpackage.data");
	SPtoAT();
}

//function reads the secretpackage and derialize it into seperate fields
void derialize(char* file) {
  	FILE *filePtr;  
  	int listLength = 0;
  	int done = 0;       
  	uint16_t arrayLen;   
  	char *buffer;

  	filePtr = fopen(file, "rb"); 

  	for(done = 0; done < 5; done++) {
    		fread(&arrayLen, 2, 1, filePtr);     
    		buffer =(char *)malloc(arrayLen + 1); 
    		fread(buffer, arrayLen, 1, filePtr);  
    		buffer[arrayLen] = '\0';
    		addToList(arrayLen, buffer);  
	}
}

//Part of the derialize process
void addToList(uint16_t arrayLen, char *buffer) {
  	list *ptr;            
  	ptr = malloc(3000); 
  	if (start == 0) {         
    		start = ptr;          
    		ptr->next = 0;     
  	} else {                 
    		end->next = ptr;       
  	}
  	end = ptr;       
  	ptr->next = 0;        
  
  	ptr->arrayLen = arrayLen;  
  	strcpy(ptr->array, buffer);
}

//creates the corresponding ATs from derialized SP
void SPtoAT() {
	list *ptr = start;
	FILE *fp;
	char IPs[2048] = "";
	char salts[2048] = "";
	char metafile[2048] = "";
	char secretkey[2048] = "";
	char privatekey[2048] = "";
	int field = 0;
  	while(ptr != 0) {
		switch(field) {
			case 0:
				strcpy(IPs, ptr->array);
				IPs[strlen(IPs)] == '\0';
				break;
			case 1:
				strcpy(salts, ptr->array);
				salts[strlen(salts)] == '\0';
				break;
			case 2:
				strcpy(metafile, ptr->array);
				char metafilename[100] = "";
				char tmpmeta[100] = "";
				strncpy(tmpmeta, ptr->array, 99);
				strcpy(metafilename, strtok(tmpmeta, "."));
				strcat(metafilename, "_meta.txt");
   				fp = fopen(metafilename, "w");
   				fwrite(metafile,1,sizeof(metafile),fp);
   				fclose(fp);
				break;
			case 3:
				strcpy(secretkey, ptr->array);
				secretkey[strlen(secretkey)] == '\0';
   				fp = fopen("secretkey.data", "w");
   				fwrite(secretkey,1,sizeof(secretkey),fp);
   				fclose(fp);
				break;
			case 4:
				strcpy(privatekey, ptr->array);
				privatekey[strlen(privatekey)] == '\0';
   				fp = fopen("private.pem", "w");
   				fwrite(privatekey,1,sizeof(privatekey),fp);
   				fclose(fp);
				break;
		}
    		ptr = ptr->next;
		field++;
  	}
	int tmpcount = 0;
	int set = 1;
	for (tmpcount = 0; tmpcount < strlen(IPs); tmpcount++) {
		if(IPs[tmpcount] == ',') {
			set++;
		}
	}
	char IPlist[set][40];
	char saltlist[set][40];
	char* tokenIP = strtok(IPs, ",");
	for(tmpcount = 0; tokenIP != NULL; tmpcount++) {
		strncpy(IPlist[tmpcount], tokenIP, 39);
		tokenIP = strtok(NULL, ",");
	}
	char* tokensalt = strtok(salts, ",");
	for(tmpcount = 0; tokensalt != NULL; tmpcount++) {
		strncpy(saltlist[tmpcount], tokensalt, 39);
		tokensalt = strtok(NULL, ",");
	}
	for(tmpcount = 0; tmpcount < set; tmpcount++) {
		AT(secretkey, saltlist[tmpcount], IPlist[tmpcount], "nv");
	}
}

//decrypts the specified file (outcome = *.decrypted)
//require - The password to decrypt and '.encrypted' files in cwd
//result - Files decrypted are named '<filename>.decrypted' 
void decrypt(char* infile) {
	char outfile[40];
	int tlength = strlen(infile) - 10;
	int ti = 0;
	while(ti < tlength) {
		outfile[ti] = infile[ti];
		ti++;
	}
	outfile[ti] = '\0';
	strcat(outfile, ".decrypted");
	updateMessages("Decrypting file ");
	updateMessage(infile);
	updateMessage("... ");
	FILE* ifp = fopen(infile, "rb");//File to be decrypted; cipher text
   	FILE* ofp = fopen(outfile, "wb");//File to be written; plain text
   	//Get file size
	fseek(ifp, 0L, SEEK_END);
   	int fsize = ftell(ifp);
   	//set back to normal
   	fseek(ifp, 0L, SEEK_SET);

   	int outLen1 = 0; int outLen2 = 0;
   	unsigned char *indata = malloc(fsize);
   	unsigned char *outdata = malloc(fsize);
   	//unsigned char ckey[] = "correctpasswords";
   	unsigned char ivec[] = "donotchangethis!";
	int pwlength = strlen((unsigned char*)gtk_entry_get_text((GtkEntry*)entry4)) / 2;
	strncpy(password1, (unsigned char*)gtk_entry_get_text((GtkEntry*)entry4), pwlength);
	password1[pwlength] = '\0';

   	//Read File
   	fread(indata,sizeof(char),fsize, ifp);//Read Entire File

   	//setup decryption
   	EVP_CIPHER_CTX ctx;
   	EVP_DecryptInit(&ctx,EVP_aes_256_cbc(),password1,ivec);
   	EVP_DecryptUpdate(&ctx,outdata,&outLen1,indata,fsize);
    	EVP_DecryptFinal(&ctx,outdata + outLen1,&outLen2);
    	fwrite(outdata,sizeof(char),outLen1 + outLen2,ofp);

    	fclose(ifp);
    	fclose(ofp);
	updateMessage("OK");
}

//decrypts all files with names *.encrypted in current directory
//require - The password to decrypt and '.encrypted' files in cwd
//result - Files decrypted are named '<filename>.decrypted'
void decryptAll() {
	if(strlen((unsigned char*)gtk_entry_get_text((GtkEntry*)entry4)) == 0) {
		updateMessages("Password cannot be empty.");
		return;
	}
	DIR *dp;
	struct dirent *ep;
	int found = 0;

	dp = opendir ("./");
	if (dp != NULL) {
		while (ep = readdir (dp)) {
			char* ext = strrchr(ep->d_name, '.');
			if(ext != NULL) {
				if(strcmp(ext, ".encrypted") == 0) {
				        decrypt(ep->d_name);
					found++;
				}
			}
		}
		(void) closedir (dp);
	}
	if(found == 0) {
		char endmessage[150];
		char cwd[100];
		getcwd(cwd, sizeof(cwd));
		sprintf(endmessage, "No encrypted files found in current directory (%s)", cwd);
		updateMessages(endmessage);
	}
}

//encrypts specified file (outcome = *.encrypted)
//require - A password to be used for the encryption
//result - An encrypted file with name '<filename>.encrypted'
int encrypt(char* infile) {
	char outfile[40];
	strcpy(outfile, infile);
	strcat(outfile, ".encrypted");
	char tmpmsg[60];
	sprintf(tmpmsg, "Encrypting file %s... ", infile);
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
    	//unsigned char ckey[] = "correctpasswords";
    	unsigned char ivec[] = "donotchangethis!";
	int pwlength = strlen((unsigned char*)gtk_entry_get_text((GtkEntry*)entry4)) / 2;
	strncpy(password1, (unsigned char*)gtk_entry_get_text((GtkEntry*)entry4), pwlength);
	password1[pwlength] = '\0';

    	//Read File
    	fread(indata,sizeof(char),fsize, ifp);//Read Entire File

    	//Set up encryption
    	EVP_CIPHER_CTX ctx;
    	EVP_EncryptInit(&ctx,EVP_aes_256_cbc(),password1,ivec);
    	EVP_EncryptUpdate(&ctx,outdata,&outLen1,indata,fsize);
    	EVP_EncryptFinal(&ctx,outdata + outLen1,&outLen2);
    	fwrite(outdata,sizeof(char),outLen1 + outLen2,ofp);
	
	char* part = strrchr(outfile, '_');	
	char* icon = strtok(part, "_m");
	if(part != NULL && isdigit(icon[0])) {
		int x = icon[0] - '0';
		strcpy(tmpfilesarray[x], outfile);
	}
    	fclose(ifp);
    	fclose(ofp);
	strcat(tmpmsg, "OK");    
	updateMessages(tmpmsg);
	
	return 0;
}

//file read for erasure coding
int jfread(void *ptr, int size, int nmembers, FILE *stream) {
  	if (stream != NULL) return fread(ptr, size, nmembers, stream);

  	MOA_Fill_Random_Region(ptr, size);
  	return size;
}

//decoding of erasure coded files. 
//require - The meta file and some or all of the encoded parts
//result - <filename>_decoded.<extension (original filename, extension)
int rs_decode () {
	char endmessage[50];
	char originalfilename[40];
	GtkWidget* dialog = gtk_dialog_new_with_buttons("", NULL, GTK_DIALOG_DESTROY_WITH_PARENT, "SELECT A META FILE", GTK_RESPONSE_ACCEPT, NULL);
		gtk_widget_show_all(dialog);
		gint resp = gtk_dialog_run(GTK_DIALOG(dialog));
		if(resp==GTK_RESPONSE_ACCEPT) {
			gtk_widget_destroy(dialog);
			char action[5] = "meta";
			int error = browseFile(NULL, NULL, action);
			if(error == 1) {
				return 1;
			}
			char* metafilename = (char*)gtk_entry_get_text((GtkEntry*)meta_entry);
			FILE* mfs = fopen(metafilename, "r");
			fgets(originalfilename, sizeof(originalfilename), mfs);
			fclose(mfs);
			originalfilename[strlen(originalfilename)-1] = '\0';
			sprintf(endmessage, "Decoding file %s", originalfilename);
			updateMessages(endmessage);
		} else {
			gtk_widget_destroy(dialog);
			return 1;
		}
	
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

	curdir = (char *)malloc(sizeof(char)*1000);
	assert(curdir == getcwd(curdir, 1000));
	
	/* Begin recreation of file names */
	cs1 = (char*)malloc(sizeof(char)*strlen(originalfilename));
	cs2 = strrchr(originalfilename, '/');
	if (cs2 != NULL) {
		cs2++;
		strcpy(cs1, cs2);
	}
	else {
		strcpy(cs1, originalfilename);
	}
	cs2 = strchr(cs1, '.');
	if (cs2 != NULL) {
                extension = strdup(cs2);
		*cs2 = '\0';
	} else {
           extension = strdup("");
        }	
	fname = (char *)malloc(sizeof(char*)*(100+strlen(originalfilename)+20));

	/* Read in parameters from metadata file */
	sprintf(fname, "%s_meta.txt", cs1);

	fp = fopen(fname, "rb");
        if (fp == NULL) {
          sprintf(endmessage, "Error: no metadata file %s\n", fname);
		updateMessages(endmessage);
          return 1;
        }
	temp = (char *)malloc(sizeof(char)*(strlen(originalfilename)+20));
	if (fscanf(fp, "%s", temp) != 1) {
		updateMessages("Metadata file - bad format");
		return 1;
	}
	
	if (fscanf(fp, "%d", &origsize) != 1) {
		updateMessages("Original size is not valid");
		return 1;
	}
	if (fscanf(fp, "%d %d %d %d %d", &k, &m, &w, &packetsize, &buffersize) != 5) {
		updateMessages("Parameters are not correct");
		return 1;
	}
	c_tech = (char *)malloc(sizeof(char)*(strlen(originalfilename)+20));
	if (fscanf(fp, "%s", c_tech) != 1) {
		updateMessages("Metadata file - bad format");
		return 1;
	}
	if (fscanf(fp, "%d", &tech) != 1) {
		updateMessages("Metadata file - bad format");
		return 1;
	}
	method = tech;
	if (fscanf(fp, "%d", &readins) != 1) {
		updateMessages("Metadata file - bad format");
		return 1;
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
			sprintf(fname, "%s_k%0*d%s%s", cs1, md, i, extension, ".decrypted");
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
			sprintf(fname, "%s_m%0*d%s%s", cs1, md, i, extension, ".decrypted");
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
			updateMessages("Metadata file - bad format");
			return 1;
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
	
	updateMessages("File has been decoded! (");
	updateMessage(fname);
	updateMessage(")");

	/* Free allocated memory */
	free(cs1);
	free(extension);
	free(fname);
	free(data);
	free(coding);
	free(erasures);
	free(erased);

	return 0;
}

//performs erasure coding on a file with K,M,W as parameters
//require - K,M,W parameters, a file to be encoded and password
//result - original file into K number of parts (*_k#.<extension>)
//result - M number of encoded parts from K (*_m#.<extension>)
//result - each encoded parts are encrypted with password to become 
//result - (*_m#.<extension>.encrypted)
int rs_encode () {
	if(strlen((unsigned char*)gtk_entry_get_text((GtkEntry*)entry4)) == 0) {
		updateMessages("Password cannot be empty.");
		return 1;
	}
	char* targv1 = (char*) gtk_entry_get_text((GtkEntry*)entry1);
	char* targv2 = (char*) gtk_entry_get_text((GtkEntry*)entry2_0);
	char* targv3 = (char*) gtk_entry_get_text((GtkEntry*)entry2_1);
	char* targv4 = (char*) gtk_entry_get_text((GtkEntry*)entry2_2);
	if(strlen(targv1) == 0 || strlen(targv2) == 0 || strlen(targv3) == 0 || strlen(targv4) == 0) {
		updateMessages("Upload file and encode options cannot be empty.");
		return 0;
	}
	updateMessages("Encoding upload file...");
	char* argv[5] = {"", targv1,targv2,targv3,targv4};
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
	packetsize = 0;
	buffersize = 0;

	/* start timing */
	//clock_t begin, end;
	//double time_spent;
	//begin = clock();

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
				//encrypts encoded files as they are created
  				encrypt(fname);
			}
		}
		n++;
	}

	

	/* Create metadata file */
        if (fp != NULL) {
		sprintf(fname, "%s_meta.txt", s1);
		//sprintf(metafilename, "%s_meta.txt", s1);
		fp2 = fopen(fname, "wb");
		char* tmpfn1 = (char*)malloc(sizeof(char)*(strlen(argv[1])+20));;
		char* tmpfn2;
		tmpfn2 = strrchr(argv[1], '/');
		strcpy(tmpfn1, ++tmpfn2);
		fprintf(fp2, "%s\n", tmpfn1);
		fprintf(fp2, "%d\n", size);
		fprintf(fp2, "%d %d %d %d %d\n", k, m, w, packetsize, buffersize);
		fprintf(fp2, "%s\n", argv[4]);
		fprintf(fp2, "%d\n", tech);
		fprintf(fp2, "%d\n", readins);
		fclose(fp2);
		gtk_entry_set_text((GtkEntry*)meta_entry, fname);
  		encrypt(fname);
	}

	/* time taken */
	//end = clock();


	/* Free allocated memory */
	free(s1);
	free(fname);
	free(block);
	free(curdir);
	
	updateMessages("Encoded files have been created.");

	//time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	//char timemessage[150] = "";
	//struct stat st;
	//stat(argv[1], &st);
	//size = st.st_size;
	//sprintf(timemessage, "Time taken to encode and encrypt %d bytes: %g ms\n", size, time_spent * 1000);
	//updateMessages(timemessage);

	return 0;
}

//generate rsa key and public/private key pair
//will not generate if key pair already exists
//result - private.pem and public.pem key pair
int generate_keys() {
    	if(access("public.pem", F_OK) != -1 && access("private.pem", F_OK) != -1) {
		return 1;
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
		updateMessages("Key pair generation failed...");
		return 1;
    	} else {
		updateMessages("Key pair generation successful!");
		return 0;
   	}
}

//write secretkey to file
//result - secretkey.data containing the secretkey
void createSecretKeyFile(char* randomString) {
    	FILE *file = fopen("secretkey.data", "wb");
    	fwrite(randomString,sizeof(char),strlen(randomString),file);
    	fclose(file);
    	updateMessages("Secret Key file created (secretkey.data)");
}

//read private key from private.pem
//require - private.pem
//result - content of private.pem to be used in secretpackage.data
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

	memcpy(privatekey, tmp, strlen(tmp));
	privatekey[strlen(tmp)] = '\0';
	//memcpy(privatekey, (tmp+32), strlen(tmp) - 63);
	//privatekey[strlen(tmp) - 63] = '\0';

	fclose(fp);
    	/*FILE *fOUT;
	fOUT = fopen("privatekey.data", "wb");
    	fwrite(privatekey,sizeof(char),strlen(privatekey),fOUT);
	fclose(fOUT);*/
}

//generate a random string of 256 characters
//result - generates the secret key
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

//read metafilecontents
//require - <filename>_meta.txt
//result - metafile contents will be used to decode a file
void getMetafileContents(char* metafilename, char* metafilecontents) {    
    	FILE *file = fopen(metafilename, "rb");
    	fseek(file, 0L, SEEK_END);
    	int fsize = ftell(file);
    	fseek(file, 0L, SEEK_SET);

    	fread(metafilecontents,sizeof(char),fsize, file);
	metafilecontents[fsize] = '\0';
}

//serialize required data into secretpackage
//require - list struct defined at the beginning of this file
void serializeList(list *item, char *buffer) {
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

//required for creation of secretpackage. Part of the serialize process
int listSize(list *item) {
  	int size = 0;
  
  	while (item != 0) {
    		size += item->arrayLen;        
    		size += sizeof(item->arrayLen); 
    		item = item->next;         
  	}
  	return size;
}

//read secretkey from file
//require - secretkey.data
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

//signing of the AT and timestamp
//require - public.pem, private.pem, AT.data
//result - generates a timestamp file and sign with AT.data
//result - produces a file AT.data.signed
//result - signed file is further verified by RSA_verify()
void AT_sign(char* ATfile, char* Mode) {
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
    	FILE* pub;
	if(strcmp(Mode, "v") == 0) {
		pub = fopen("public.pem", "rb");
	}

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

	if(strcmp(Mode, "v") == 0) {
		public_key = PEM_read_RSAPublicKey(pub, NULL, NULL, NULL); 
	   	if(public_key == NULL) { 
	      		ERR_print_errors_fp(stdout); 
	   	} 
		verified = RSA_verify(NID_sha1, (unsigned char*) message, 
		strlen(message), signedinput, 256, public_key); 

		///////////////////////////////////////////////////// 

		char endmessage[3];
		sprintf(endmessage, "%d", verified);
		updateMessages("Authentication Token signed - VERIFIED: ");
		updateMessage(endmessage);
	}
}

//creating the Authentication Token
//require - secretkey, IP addresses and salt values for each IP
//require - Mode prevents doing verification for loading of external SP.
//require - this is because public key might not be present.
//result - files AT<IP:port>.data; contains hashed value of each AT.  
void AT(char* sk, char* salt, char* IP, char* Mode) {
	int pwlength = strlen((unsigned char*)gtk_entry_get_text((GtkEntry*)entry4)) / 2;
	strncpy(password2, ((unsigned char*)gtk_entry_get_text((GtkEntry*)entry4))+pwlength, pwlength + (strlen((unsigned char*)gtk_entry_get_text((GtkEntry*)entry4)) % 2));
	password2[pwlength + (strlen((unsigned char*)gtk_entry_get_text((GtkEntry*)entry4)) % 2)] = '\0';

	unsigned char at[512] = "";
	strcat(at, sk);
	strcat(at, password2);
	strcat(at, salt);
	at[strlen(at)] = '\0';

	//hashing of sk+pw2+salt
   	int i = 0;
    	unsigned char temp[SHA_DIGEST_LENGTH];
    	char buf[SHA_DIGEST_LENGTH*2];

    	memset(buf, 0x0, SHA_DIGEST_LENGTH*2);
    	memset(temp, 0x0, SHA_DIGEST_LENGTH);

	SHA1((unsigned char *)at, strlen(at), temp);

	for (i=0; i < SHA_DIGEST_LENGTH; i++) {
	        sprintf((char*)&(buf[i*2]), "%02x", temp[i]);
   	}
	temp[strlen(temp)] = '\0';
	buf[strlen(buf)] = '\0';
	char hash[41] = "";
	strncpy(hash, buf, 40);
	hash[40] = '\0';
	//hash stored in -> hash

	char ATfile[60] = "";
	strcat(ATfile, "AT");
	strcat(ATfile, IP);
	strcat(ATfile, ".data");

    	FILE *ATout = NULL;
	ATout = fopen(ATfile, "wb");
    	fwrite(hash,sizeof(char),strlen(hash),ATout);
	fclose(ATout);
	updateMessages("Authentication Token created for ");
	updateMessage(IP);
	char* clear = "";
	printf("%s", clear);
	AT_sign(ATfile, Mode);
}

//create the secretpackage
//require - IP addresse(s), salt(s), secretkey, metafile & privatekey
//result - secretpackage.data
//result - this function automatically calls the AT() to create AT(s) 
//result - after secretpackage.data is created.
void createSecretPackage(GtkWidget* widget, char* iptoken) {
	if(strlen((unsigned char*)gtk_entry_get_text((GtkEntry*)entry4)) == 0) {
		updateMessages("Password cannot be empty.");
		return;
	}
	char ip[200] = "";
	char saltvalue[200] = "";
	char randomString[260] = "";
	char privatekey[2048] = "";
	if(strlen(iptoken) == 0) {
		strncpy(ip, (char*)gtk_entry_get_text((GtkEntry*)entry3), 199);
	} else {
		strncpy(tmpwholeip, (char*)gtk_entry_get_text((GtkEntry*)entry3), 199);
		sprintf(ip, "%s", tmpwholeip);
	}
	ip[strlen(ip)] = '\0';
	if(strlen(ip) == 0) {
		updateMessages("IP Address cannot be empty.");
		return;
	}
	//using a salt that is the same as its ip address 
	strncpy(saltvalue, ip, 199);
	saltvalue[strlen(saltvalue)] = '\0';
	char metafilecontents[2048];
	char* metafilename = (char*)gtk_entry_get_text((GtkEntry*)meta_entry);
	if(strlen(metafilename) == 0) {
		updateMessages("Meta file not found.");
		GtkWidget* dialog = gtk_dialog_new_with_buttons("Select a meta file?", NULL, GTK_DIALOG_MODAL, "          YES          ", GTK_RESPONSE_ACCEPT, "          NO          ", GTK_RESPONSE_REJECT, NULL);
		gtk_widget_show_all(dialog);
		gint resp = gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		if(resp==GTK_RESPONSE_ACCEPT) {
			char action[5] = "meta";
			int error = browseFile(NULL, NULL, action);
			if(error == 1) {
				return;
			}
			metafilename = (char*)gtk_entry_get_text((GtkEntry*)meta_entry);
		} else {
			return;
		}
	}
	getMetafileContents(metafilename, metafilecontents);
	getSecretKey(randomString);
	int error = generate_keys();
	if(error == 1) {
		updateMessages("Public and Private keys exist.");
	}
	getPrivateKey(privatekey);

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
  	updateMessages("Secret Package has been created (secretpackage.data)");
  	encrypt("secretpackage.data");
	
	int tmpcount = 0;
	int set = 1;
	for (tmpcount = 0; tmpcount < strlen(ip); tmpcount++) {
		if(ip[tmpcount] == ',') {
			set++;
		}
	}
	char IPlist[set][40];
	char saltlist[set][40];
	char* tokenIP = strtok(ip, ",");
	for(tmpcount = 0; tokenIP != NULL; tmpcount++) {
		strncpy(IPlist[tmpcount], tokenIP, 39);
		tokenIP = strtok(NULL, ",");
	}
	char* tokensalt = strtok(saltvalue, ",");
	for(tmpcount = 0; tokensalt != NULL; tmpcount++) {
		strncpy(saltlist[tmpcount], tokensalt, 39);
		tokensalt = strtok(NULL, ",");
	}
	for(tmpcount = 0; tmpcount < set; tmpcount++) {
		AT(randomString, saltlist[tmpcount], IPlist[tmpcount], "v");
	}
}

//function saves encrypted secretpackage to a selected path.
//require - ENCRYPTED secret package
//result - encrypted secret package is saved to the selected path.
void saveSP() {
	int chk = checkFileExist("secretpackage.data.encrypted");
	if(chk == 1) {
		browseFile(NULL, NULL, "save");
		system("./reset.sh");
	} else {
		updateMessages("No SP found in current directory.");
	}
}

//pressing 'Setup' set up the client and svrs for demo
//require - ALL corresponding svrs to be listening. ALL fields filled.
//require - number of encoded parts to be same as no. of servers.
//require - one or more IP:port pairs. Seperate with 'comma(,)'.
//result - if SP or publickey missing, SP and ATs are newly created.
//result - Subsequently, ATs and public key are updated to the servers.
//result - each part of encoded file is uploaded to each server.
void setupButton() {
	char iparray[20][50];
	int x = 0;
	if(strlen((char*)gtk_entry_get_text((GtkEntry*)entry1)) == 0) {
		updateMessages("Please select a file.");
		return;
	}
	if(strlen((char*)gtk_entry_get_text((GtkEntry*)entry2_0)) == 0) {
		updateMessages("Encoding options cannot be empty.");
		return;
	}
	if(strlen((char*)gtk_entry_get_text((GtkEntry*)entry2_1)) == 0) {
		updateMessages("Encoding options cannot be empty.");
		return;
	}
	if(strlen((char*)gtk_entry_get_text((GtkEntry*)entry3)) == 0) {
		updateMessages("IP cannot be empty.");
		return;
	}
	if(checkFileExist("public.pem") != 1 && checkFileExist("secretpackage.data") == 1) {
		updateMessages("Error: Setup cannot be done without public.pem");
		return;
	}
	char wholeip[100] = "";
	char *iptoken;
	char iptokentmp[50] = "";
	strncpy(wholeip, (char*)gtk_entry_get_text((GtkEntry*)entry3), 99);
	iptoken = strtok(wholeip, ",");
	while( iptoken != NULL ) {
		sprintf(iparray[x], "%s", iptoken);
		x++;
		iptoken = strtok(NULL, ",");
	}
	int addresses = atoi((char*)gtk_entry_get_text((GtkEntry*)entry2_1));
	if(addresses != x) {
		updateMessages("Encoding option 'm' does not match the number of addresses");
		return;
	}
	rs_encode();	
	if(checkFileExist("secretpackage.data") != 1) {
		createSecretPackage(NULL, wholeip);
	}

	int i = 0;
	for(i = 0; i < x; i++) {
		int error = connectTo(NULL, iparray[i]);
		if(error == 1) {
			updateMessages("Unable to establish connection with ");
			updateMessage(iparray[i]);
			continue;
		}
		updateSvrAT(NULL, iparray[i]);
		upload(NULL, iparray[i]);
		disconnectFrom(NULL, iparray[i]);
	}
}

//main. GUI. 
//require - gf_complete, Jerasure, crypto, and GTK libraries
int main(int argc, char* argv[]) {
	GtkWidget *browseb, *lbrowseb;
	GtkWidget *spb, *lspb;
	GtkWidget *showdb, *lshowdb;
	GtkWidget *savespb, *lsavespb;
	GtkWidget *encodeb, *lencodeb;
	GtkWidget *decodeb, *ldecodeb;
	GtkWidget *decryptb, *ldecryptb;
	GtkWidget *b0, *lb0, *b1, *lb1, *b2, *lb2, *b3, *lb3;


	gtk_init(&argc, &argv);

	myfont = pango_font_description_from_string("Arial 14");

	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
	gtk_window_set_title(GTK_WINDOW(window), "Main");
	gtk_window_set_default_size(GTK_WINDOW(window), 750, 400);
	gtk_container_set_border_width(GTK_CONTAINER(window), 10);
	
	frame = gtk_fixed_new();
	gtk_container_add(GTK_CONTAINER(window), frame);
	//upload file name
	label1 = gtk_label_new("File");
	gtk_widget_modify_font(label1, myfont);
	gtk_fixed_put(GTK_FIXED(frame), label1, 5, 14);

	entry1 = gtk_entry_new();
	gtk_widget_modify_font(entry1, myfont);
	gtk_entry_set_width_chars((GtkEntry*) entry1, 42);
	gtk_fixed_put(GTK_FIXED(frame),entry1, 180, 10);
	gtk_widget_set_sensitive(entry1, FALSE);
	//encode options
	label2 = gtk_label_new("Encode (k,m,w)");
	gtk_widget_modify_font(label2, myfont);
	gtk_fixed_put(GTK_FIXED(frame), label2, 5, 54);
	
	entry2_0 = gtk_entry_new();
	gtk_widget_modify_font(entry2_0, myfont);
	gtk_entry_set_width_chars((GtkEntry*) entry2_0, 4);
	gtk_fixed_put(GTK_FIXED(frame),entry2_0, 180, 50);

	entry2_1 = gtk_entry_new();
	gtk_widget_modify_font(entry2_1, myfont);
	gtk_entry_set_width_chars((GtkEntry*) entry2_1, 4);
	gtk_fixed_put(GTK_FIXED(frame),entry2_1, 235, 50);

	entry2_2 = gtk_entry_new();
	gtk_widget_modify_font(entry2_2, myfont);
	gtk_entry_set_width_chars((GtkEntry*) entry2_2, 4);
	gtk_fixed_put(GTK_FIXED(frame),entry2_2, 290, 50);
	gtk_entry_set_text((GtkEntry*)entry2_2, "8");
	//ip address
	label3 = gtk_label_new("IP:Port");
	gtk_widget_modify_font(label3, myfont);
	gtk_fixed_put(GTK_FIXED(frame), label3, 5, 94);

	entry3 = gtk_entry_new();
	gtk_widget_modify_font(entry3, myfont);
	gtk_entry_set_width_chars((GtkEntry*) entry3, 27);
	gtk_fixed_put(GTK_FIXED(frame),entry3, 180, 90);
	gtk_entry_set_text((GtkEntry*)entry3, "127.0.0.1:10000,127.0.0.1:10001,127.0.0.1:10002");

	//buttons for demo purpose
	lb0 = gtk_label_new("-");
	gtk_widget_modify_font(lb0, myfont);
	b0 = gtk_button_new();
	gtk_container_add(GTK_CONTAINER(b0), lb0);
	gtk_fixed_put(GTK_FIXED(frame), b0, 162, 90);
	lb1 = gtk_label_new("1");
	gtk_widget_modify_font(lb1, myfont);
	b1 = gtk_button_new();
	gtk_container_add(GTK_CONTAINER(b1), lb1);
	gtk_fixed_put(GTK_FIXED(frame), b1, 102, 90);
	lb2 = gtk_label_new("2");
	gtk_widget_modify_font(lb2, myfont);
	b2 = gtk_button_new();
	gtk_container_add(GTK_CONTAINER(b2), lb2);
	gtk_fixed_put(GTK_FIXED(frame), b2, 122, 90);
	lb3 = gtk_label_new("3");
	gtk_widget_modify_font(lb3, myfont);
	b3 = gtk_button_new();
	gtk_container_add(GTK_CONTAINER(b3), lb3);
	gtk_fixed_put(GTK_FIXED(frame), b3, 142, 90);
	g_signal_connect(b0, "clicked", G_CALLBACK(d0), NULL);
	g_signal_connect(b1, "clicked", G_CALLBACK(d1), NULL);
	g_signal_connect(b2, "clicked", G_CALLBACK(d2), NULL);
	g_signal_connect(b3, "clicked", G_CALLBACK(d3), NULL);

	//password
	label4 = gtk_label_new("Password");
	gtk_widget_modify_font(label4, myfont);
	gtk_fixed_put(GTK_FIXED(frame), label4, 5, 134);

	entry4 = gtk_entry_new();
	gtk_widget_modify_font(entry4, myfont);
	gtk_entry_set_width_chars((GtkEntry*) entry4, 27);
	gtk_fixed_put(GTK_FIXED(frame), entry4, 180, 130);
	gtk_entry_set_text((GtkEntry*)entry4, "password");

	//hidden fields
	meta_entry = gtk_entry_new();
	download_entry = gtk_entry_new();
	auto_entry = gtk_entry_new();
	sp_entry = gtk_entry_new();

	//buttons
	lbrowseb = gtk_label_new("   Browse   ");
	gtk_widget_modify_font(lbrowseb, myfont);
	browseb = gtk_button_new();
	gtk_container_add(GTK_CONTAINER(browseb), lbrowseb);
	gtk_fixed_put(GTK_FIXED(frame), browseb, 615, 9);

	lencodeb = gtk_label_new("Encode & Encrypt");
	gtk_widget_modify_font(lencodeb, myfont);
	encodeb = gtk_button_new();
	gtk_container_add(GTK_CONTAINER(encodeb), lencodeb);
	gtk_fixed_put(GTK_FIXED(frame), encodeb, 340, 48);

	ldecodeb = gtk_label_new("Decode File ");
	gtk_widget_modify_font(ldecodeb, myfont);
	decodeb = gtk_button_new();
	gtk_container_add(GTK_CONTAINER(decodeb), ldecodeb);
	gtk_fixed_put(GTK_FIXED(frame), decodeb, 499, 48);

	ldecryptb = gtk_label_new("Decrypt All ");
	gtk_widget_modify_font(ldecryptb, myfont);
	decryptb = gtk_button_new();
	gtk_container_add(GTK_CONTAINER(decryptb), ldecryptb);
	gtk_fixed_put(GTK_FIXED(frame), decryptb, 615, 48);

	lconnectb = gtk_label_new("  Connect   ");
	gtk_widget_modify_font(lconnectb, myfont);
	connectb = gtk_button_new();
	gtk_container_add(GTK_CONTAINER(connectb), lconnectb);
	gtk_fixed_put(GTK_FIXED(frame), connectb, 615, 87);

	ldisconnectb = gtk_label_new("Disconnect");
	gtk_widget_modify_font(ldisconnectb, myfont);
	disconnectb = gtk_button_new();
	gtk_container_add(GTK_CONTAINER(disconnectb), ldisconnectb);
	gtk_fixed_put(GTK_FIXED(frame), disconnectb, 615, 87);

	luploadb = gtk_label_new("   Upload    ");
	gtk_widget_modify_font(luploadb, myfont);
	uploadb = gtk_button_new();
	gtk_container_add(GTK_CONTAINER(uploadb), luploadb);
	gtk_fixed_put(GTK_FIXED(frame), uploadb, 615, 126);

	ldownloadb = gtk_label_new(" Download ");
	gtk_widget_modify_font(ldownloadb, myfont);
	downloadb = gtk_button_new();
	gtk_container_add(GTK_CONTAINER(downloadb), ldownloadb);
	gtk_fixed_put(GTK_FIXED(frame), downloadb, 616, 204);

	lupdateb = gtk_label_new("   Update    ");
	gtk_widget_modify_font(lupdateb, myfont);
	updateb = gtk_button_new();
	gtk_container_add(GTK_CONTAINER(updateb), lupdateb);
	gtk_fixed_put(GTK_FIXED(frame), updateb, 615, 165);

	lspb = gtk_label_new(" Create AT ");
	gtk_widget_modify_font(lspb, myfont);
	spb = gtk_button_new();
	gtk_container_add(GTK_CONTAINER(spb), lspb);
	gtk_fixed_put(GTK_FIXED(frame), spb, 460, 88);

	lchoosespb = gtk_label_new("Choose SP");
	gtk_widget_modify_font(lchoosespb, myfont);
	choosespb = gtk_button_new();
	gtk_container_add(GTK_CONTAINER(choosespb), lchoosespb);
	gtk_fixed_put(GTK_FIXED(frame), choosespb, 460, 129);
	
	lshowdb = gtk_label_new("ShowDe");
	gtk_widget_modify_font(lshowdb, myfont);
	showdb = gtk_button_new();
	gtk_container_add(GTK_CONTAINER(showdb), lshowdb);
	gtk_fixed_put(GTK_FIXED(frame), showdb, 650, 245);

	lsavespb = gtk_label_new("SaveSP");
	gtk_widget_modify_font(lsavespb, myfont);
	savespb = gtk_button_new();
	gtk_container_add(GTK_CONTAINER(savespb), lsavespb);
	gtk_fixed_put(GTK_FIXED(frame), savespb, 650, 280);

	lautob = gtk_label_new("  Setup  ");
	gtk_widget_modify_font(lautob, myfont);
	autob = gtk_button_new();
	gtk_container_add(GTK_CONTAINER(autob), lautob);
	gtk_fixed_put(GTK_FIXED(frame), autob, 650, 315);

	lqb = gtk_label_new("   Quit   ");
	gtk_widget_modify_font(lqb, myfont);
	qb = gtk_button_new();
	gtk_container_add(GTK_CONTAINER(qb), lqb);
	gtk_fixed_put(GTK_FIXED(frame), qb, 650, 350);

	//message
	gm0 = gtk_label_new("");
	gm1 = gtk_label_new("");
	gm2 = gtk_label_new("");
	gm3 = gtk_label_new("");
	gm4 = gtk_label_new("");
	gm5 = gtk_label_new("");
	gm6 = gtk_label_new("");
	gm7 = gtk_label_new("");
	gm8 = gtk_label_new("");
	gm9 = gtk_label_new("");
	gtk_widget_modify_font(gm0, myfont);
	gtk_widget_modify_font(gm1, myfont);
	gtk_widget_modify_font(gm2, myfont);
	gtk_widget_modify_font(gm3, myfont);
	gtk_widget_modify_font(gm4, myfont);
	gtk_widget_modify_font(gm5, myfont);
	gtk_widget_modify_font(gm6, myfont);
	gtk_widget_modify_font(gm7, myfont);
	gtk_widget_modify_font(gm8, myfont);
	gtk_widget_modify_font(gm9, myfont);
	gtk_fixed_put(GTK_FIXED(frame), gm0, 5, 170);
	gtk_fixed_put(GTK_FIXED(frame), gm1, 5, 190);
	gtk_fixed_put(GTK_FIXED(frame), gm2, 5, 210);
	gtk_fixed_put(GTK_FIXED(frame), gm3, 5, 230);
	gtk_fixed_put(GTK_FIXED(frame), gm4, 5, 250);
	gtk_fixed_put(GTK_FIXED(frame), gm5, 5, 270);
	gtk_fixed_put(GTK_FIXED(frame), gm6, 5, 290);
	gtk_fixed_put(GTK_FIXED(frame), gm7, 5, 310);
	gtk_fixed_put(GTK_FIXED(frame), gm8, 5, 330);
	gtk_fixed_put(GTK_FIXED(frame), gm9, 5, 350);

	//show all
	gtk_widget_show_all(window);
	gtk_widget_hide(disconnectb);
	//gtk_widget_hide(choosespb);
	gtk_widget_set_sensitive(uploadb, FALSE);
	gtk_widget_set_sensitive(updateb, FALSE);
	gtk_widget_set_sensitive(downloadb, FALSE);
	gtk_widget_set_sensitive(entry2_2, FALSE);

	//button clicks -> invoke functions in G_CALLBACK()
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);	
	g_signal_connect(browseb, "clicked", G_CALLBACK(browseFile), NULL);
	g_signal_connect(encodeb, "clicked", G_CALLBACK(rs_encode), NULL);
	g_signal_connect(decodeb, "clicked", G_CALLBACK(rs_decode), NULL);
	g_signal_connect(decryptb, "clicked", G_CALLBACK(decryptAll), NULL);
	g_signal_connect(connectb, "clicked", G_CALLBACK(connectTo), (char*)"c");
	g_signal_connect(disconnectb, "clicked", G_CALLBACK(disconnectFrom), (char*)"d");
	g_signal_connect(uploadb, "clicked", G_CALLBACK(upload), (char*)"");
	g_signal_connect(updateb, "clicked", G_CALLBACK(updateSvrAT), (char*)"");
	g_signal_connect(downloadb, "clicked", G_CALLBACK(download), NULL);
	g_signal_connect(spb, "clicked", G_CALLBACK(createSecretPackage), (char*)"");
	g_signal_connect(choosespb, "clicked", G_CALLBACK(chooseSP), NULL);
	g_signal_connect(showdb, "clicked", G_CALLBACK(showDecodedFile), NULL);
	g_signal_connect(savespb, "clicked", G_CALLBACK(saveSP), NULL);
	g_signal_connect(autob, "clicked", G_CALLBACK(setupButton), NULL);
	g_signal_connect(qb, "clicked", G_CALLBACK(gtk_main_quit), NULL);

	gtk_main();

	return 0;
	
}

//creates the message output dialog
//call updateMessages(char*) to print new message
void updateMessages(char* newMessage) {
	gtk_label_set_label((GtkLabel*)gm0, gtk_label_get_text((GtkLabel*) gm1));
	gtk_label_set_label((GtkLabel*)gm1, gtk_label_get_text((GtkLabel*) gm2));
	gtk_label_set_label((GtkLabel*)gm2, gtk_label_get_text((GtkLabel*) gm3));
	gtk_label_set_label((GtkLabel*)gm3, gtk_label_get_text((GtkLabel*) gm4));
	gtk_label_set_label((GtkLabel*)gm4, gtk_label_get_text((GtkLabel*) gm5));
	gtk_label_set_label((GtkLabel*)gm5, gtk_label_get_text((GtkLabel*) gm6));
	gtk_label_set_label((GtkLabel*)gm6, gtk_label_get_text((GtkLabel*) gm7));
	gtk_label_set_label((GtkLabel*)gm7, gtk_label_get_text((GtkLabel*) gm8));
	gtk_label_set_label((GtkLabel*)gm8, gtk_label_get_text((GtkLabel*) gm9));
	gtk_label_set_label((GtkLabel*)gm9, newMessage);
}

//update the latest message
//call updateMessage(char*) to append message to latest message
void updateMessage(char* message) {
	char extra[2048] = "";
	strcpy(extra, gtk_label_get_text((GtkLabel*)gm9));
	strcat(extra, message);
	gtk_label_set_label((GtkLabel*)gm9, extra);
}

//as the function name implies
//returns 1 if file exist. else 0
int checkFileExist(char* file) {
	DIR *dp;
	struct dirent *ep;
	int found = 0;

	dp = opendir ("./");
	if (dp != NULL) {
		while (ep = readdir (dp)) {
			if(strcmp(ep->d_name, file) == 0) {
				found = 1;
			}
		}
		(void) closedir (dp);
	}
	return found;
}







