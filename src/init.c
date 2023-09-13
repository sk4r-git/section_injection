#include "../includes/init.h"

#include <argp.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <bfd.h>
#include <fcntl.h>


error_t option_parser(int key, char * arg, struct argp_state * state){
  Arguments * arguments = state->input;
  switch (key){
    case 'v' : arguments->verbose = true; break;
    case 'a' : printf("[1] an elf to analyzed\n"\
                      "[2] a binary file to inject\n"\
                      "[3] the name of the injected section\n"\
                      "[4] the base address to inject code\n"\
                      "[5] a bool to indicate if the entry "\
                          "function should be modified or not\n");
                arguments->arg = true; break; 
    case ARGP_KEY_ARG : arguments->args[state->arg_num] = arg; break;
    case ARGP_KEY_END : 
      if (state->arg_num == 5){
        arguments->ready = true;
      }
      break;
    default : return ARGP_ERR_UNKNOWN;
  }
  return 0;
}


Objects * init_objects(Arguments arguments){
  Objects * objects = malloc(sizeof(Objects));
  if (!objects){
    printf("error on malloc");
    return 0;
  }

  objects->address = strtol(arguments.args[3], NULL, 10);
  if (objects->address == 0){
    printf("error on getting the address\n");
    free(objects);
    return 0;
  }

  objects->entry = strtol(arguments.args[4], NULL, 10) ? true : false;

  objects->section = arguments.args[2];

  objects->payload = open(arguments.args[1], O_RDONLY);
  if (!objects->payload){
    printf("error on opening the payload\n");
    free(objects);
    return 0;
  }
  
  objects->target = bfd_openr(arguments.args[0], NULL);

  if (!objects->target){
    printf("error on making a bfd file\n");
    close(objects->payload);
    free(objects);
    return 0;
  }

  /*init bfd object*/
  if (!bfd_check_format(objects->target, bfd_object)){
    printf("cant cast in good format\n");
    close(objects->payload);
    bfd_close(objects->target);
    free(objects);
    return 0;
  }

  /*check for exec_type*/
  if (!(objects->target->flags & EXEC_P)){
    printf("file is not executable\n");
    close(objects->payload);
    bfd_close(objects->target);
    free(objects);
    return 0;
  }

  /*check for arch*/
  if (objects->target->arch_info->arch != bfd_mach_x86_64){
    printf("this is not x64\n");
    close(objects->payload);
    bfd_close(objects->target);
    free(objects);
    return 0;
  }

  /*check for elf*/
  if (objects->target->xvec->flavour != bfd_target_elf_flavour){
    printf("this is not an elf\n");
    close(objects->payload);
    bfd_close(objects->target);
    free(objects);
    return 0;
  }

  return objects;
}

void close_objects(Objects * objects){
  bfd_close(objects->target);
  close(objects->payload);
  free(objects);
  return;
}