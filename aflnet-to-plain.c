#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char *argv[]) {

  if(argc < 2) {
    printf("Usage: %s <input file>\n", argv[0]);
    exit(1);
  }


  char * infile = argv[1];

  char outfile[FILENAME_MAX + 6];
  snprintf(outfile, strlen(infile) + 6 + 1, "%s.plain", infile);

  printf("Input file: %s\n", infile);
  printf("Output file: %s\n", outfile);



  FILE * input_fd = fopen(infile, "rb");

  if(!input_fd) {
    perror("Unable to open input file");
    exit(1);
  }

  FILE * output_fd = fopen(outfile, "wb");

  if(!output_fd) {
    perror("Unable to open output file");
    exit(1);
  }



  int len;
  int ret;

  ret = fread(&len, sizeof(int), 1, input_fd);

  while(ret > 0) {

	  printf("Len: %d\n", len);

      char * buffer = malloc(len);;

	  ret = fread(buffer, sizeof(char), len, input_fd);

	  ret = fwrite(buffer, sizeof(char), len, output_fd);

      free(buffer);


	  ret = fread(&len, sizeof(int), 1, input_fd);
  }

  fclose(input_fd);
  fclose(output_fd);

}
