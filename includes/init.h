#ifndef INIT_H
#define INIT_H

#include <argp.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <bfd.h>


typedef struct objects{
  bfd * target;
  int payload;
  char * section;
  long int address;
  bool entry;
}Objects;

typedef struct arguments{
  bool verbose;
  bool arg;
  bool ready;   
  char * args[5];
}Arguments;

/*parse options and arguments*/
error_t option_parser(int key, char * arg, struct argp_state * state);

/*initialize arguments in a bfd way*/
Objects * init_objects(Arguments arguments);
void close_objects(Objects * objects);

#endif