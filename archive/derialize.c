#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

/* this is the same structure we have in serialize.c */
typedef struct item {
  uint16_t arrayLen; /* using fixed width integers for portability */
  char array[2048];
  struct item *next;
} list;

/* start and end of the linked list */
list *start = 0;
list *end = 0;

void addToList(uint16_t arrayLen, char *buffer)
{
  list *ptr;            
  ptr = malloc(4000); 
  if (start == 0) {         
    start = ptr;          
    ptr->next = 0;     
  }
  else {                 
    end->next = ptr;       
  }
  end = ptr;       
  ptr->next = 0;        
  
  ptr->arrayLen = arrayLen;  
  strcpy(ptr->array, buffer);
}

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
    buffer[arrayLen + 1] = '\0';    
    addToList(arrayLen, buffer);  
  }
}

void printList (list *ptr)
{
  while(ptr != 0) {
    printf("arrayLen: %i, array: %s\n", ptr->arrayLen, ptr->array);
    ptr = ptr->next;
  }
}

int main(int argc, char* argv[]) 
{
	if(argc != 2) {
		printf("usage: sourcefile\n");
		exit(0);
	}
	derialize(argv[1]);
	printList(start);
        return 0;
}



