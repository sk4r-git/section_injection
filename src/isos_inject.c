#include <argp.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <bfd.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/mman.h>

#include "../includes/init.h"
#include "../includes/elf_parse.h"


int main (int argc, char ** argv){

  Arguments arguments;
    arguments.verbose = false;
    arguments.arg = false;
    arguments.ready = false;

  static char args_doc[] = "--args for more information on arguments";
  static char doc[] = "a program to inject arbitrary code in a binary";
  /*name, key, arg, flag, doc*/
  struct argp_option options[] ={
    {"verbose", 'v', NULL, OPTION_ARG_OPTIONAL, "display verbose output", 0},
    {"args", 'a', NULL, OPTION_ARG_OPTIONAL, "list the arguments needed by the program to work", 0},
    {0},
  };

  struct argp argp = {options, option_parser, args_doc, doc, NULL, NULL, NULL};
  argp_parse(&argp, argc, argv, 0, 0, &arguments);
  
  if (!arguments.ready){
    return 0;
  }
  
  Objects * objects = init_objects(arguments);
  close_objects(objects);

  /*on recupère l'offset à modifier pour la got, 
   c'est moche mais j'ai trouvé que ca */
  FILE * fp;
  char got_getenv[8];
  char command[254];
  if(snprintf(command, 254, "objdump -d %s | tail -n+$(objdump -d ./date | "
                            "grep -n '<getenv@plt>:' | cut --delimiter=':' -f1) | "
                            "head -n2 | tail -n1 | cut --delimiter='#' -f2 | "
                            "cut --delimiter='<' -f1 | tr -d [:blank:]", arguments.args[0]) < 0){
                              exit(0);
                            }
  fp = popen(command, "r");
  if(fgets(got_getenv,sizeof(got_getenv)-1, fp) == NULL){
    exit(0);
  } 
  
  pclose(fp);
  int got_int = strtol(got_getenv, NULL, 16);
  /*objdump nous donne des adresses chargées, nous avons besoin de 
  remettre ce resultat a un offset correspondant dans le fichier binaire
  (pas sur que ça marche à tout les coups)*/
  got_int %= 0x100000;



  /*declaration of needed objects*/
  int payload = 0;
  int exec = 0;
  unsigned char * mapped = NULL;
  Elf64_Ehdr * elf_header = malloc(sizeof(Elf64_Ehdr));
  Elf64_Phdr * prg_header = malloc(sizeof(Elf64_Phdr));
  Elf64_Shdr * shstrtab = malloc(sizeof(Elf64_Shdr));
  Elf64_Shdr * sec_header = malloc(sizeof(Elf64_Shdr));



  /*initialisation of them*/
  if (!elf_header){
    printf("error on malloc elf header\n");
    goto close_all;
  }
  if (!prg_header){
    printf("error on malloc prg header\n");
    goto close_all;
  }
  if (!shstrtab){
    printf("error on malloc shstrtab\n");
    goto close_all;
  }
  if (!sec_header){
    printf("error on malloc prg header\n");
    goto close_all;
  }

  exec = open(arguments.args[0], O_RDWR);
  if (exec == -1){
    printf("error on open exec\n");
    goto close_all;
  }

  payload = open(arguments.args[1], O_RDWR);
  if (payload == -1){
    printf("error on open payload\n");
    goto close_all;
  }

  off_t size = lseek(exec, 0, SEEK_END);
  mapped = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, exec, 0);
  if (!mapped){
    printf("error on mapping elf file\n");
    goto close_all;
  }

  /*parse the elf header*/

  map_to_elf_hdr(mapped, elf_header);

  /*parsing each segment header and look for the PT_NOTE one*/
  int pt_note_ndx = 0;
  bool pt_note_find = false;

  for (pt_note_ndx = 0; pt_note_ndx < elf_header->e_phnum; pt_note_ndx++){
    map_to_prg_hdr(mapped, pt_note_ndx, elf_header, prg_header);
    if (prg_header->p_type == PT_NOTE){
      pt_note_find = true;
      break;
    }
  }

  if (!pt_note_find){
    printf("can't find pt_note segment.\n");
    goto close_all;
  }
  
  
  /*modifing the entry point and save
  the old one to write it in the payload*/
  int old_ep = elf_header->e_entry;

  off_t s_payload = lseek(payload, 0, SEEK_END);
  /*modifiing the payload depending on the old entrypoint*/
  /* 6 = 1 byte return 
        + 3 bytes jmp r10
        + 2 bytes pop r10*/
  if (strtol(arguments.args[4], NULL, 10)){
    lseek(payload, s_payload - 6, SEEK_SET);
    char save[6];
    if(read(payload, &save, 6) < 0){
      goto close_all;
    }
    lseek(payload, s_payload - 6, SEEK_SET);
    char to_write[5];
    to_write[0] = 0x68;
    to_write[1] = old_ep % 0x100;
    to_write[2] = (old_ep >> 8) % 0x100;
    to_write[3] = (old_ep >> 16) % 0x100;
    to_write[4] = (old_ep >> 24) % 0x100;
    if(write(payload, &to_write, 5) < 0){
      goto close_all;
    }
    if(write(payload, &save, 6) < 0){
      goto close_all;
    }
  }
  /*append the payload to the end of the elf*/
  char temp = 0;
  s_payload = lseek(payload, 0, SEEK_END);
  lseek(exec, size, SEEK_SET);
  lseek(payload, 0, SEEK_SET);
  /*il ne voulait pas reconnaitre le EOF... dans un fichier bin*/
  for (off_t i = 0; i < s_payload; i++){
    if(read(payload, &temp, 1) < 0){
      goto close_all;
    }
    if(write(exec, &temp, 1) < 0){
      goto close_all;
    }
  }

  /*adjust the virtual addresse of the new section*/
  size_t seg_offset = size;
  size_t virt_addr = strtol(arguments.args[3], NULL, 10);
  size_t dec = seg_offset - virt_addr;
  dec %= 4096;
  if (dec < 0) dec += 4096;
  virt_addr += dec;
  map_to_sec_hdr(mapped, elf_header->e_shstrndx, elf_header, shstrtab);
  

  /*initialize strtab to search good string*/
  unsigned char ** strtab = malloc(elf_header->e_shnum * sizeof(char *));
  if(!strtab){
    printf("error on malloc strtab\n");
    goto close_all;
  }
  for (int i = 0; i < elf_header->e_shnum; i++){
    strtab[i] = malloc(shstrtab->sh_size);
    if(!strtab[i]){
      for (int j = 0; j < i; j++){
        free(strtab[j]);
      }
      free(strtab);
      goto close_all;
    }
  }

  /*fill this tab with the good part of the mapped file*/
  int ndx = 1;
  for (unsigned long i = 0; i < elf_header->e_shnum; i++){
    int j = 0;
    do{
      strtab[i][j] = *(mapped + shstrtab->sh_offset + ndx);
      j++;
      ndx++;
    }while (strtab[i][j-1] != '\0');
  }

  /*search for the index of the good section*/
  unsigned long abi_ndx;
  char *abi_note = ".note.ABI-tag";
  for (abi_ndx = 0; abi_ndx < elf_header->e_shnum; abi_ndx++){
    bool find = true;
    for (unsigned long i = 0; i < strlen(abi_note); i++){
      if (abi_note[i] != strtab[abi_ndx][i]){
        find = false;
        break;
      }
    }
    if (find){
      break;
    }
  }

  /*save the good index of abi string*/
  unsigned long ndx_of_abi_in_strtab = 1;
  for (unsigned long i = 0; i < abi_ndx; i++){
    int j = -1;
    do{
      ndx_of_abi_in_strtab++;
      j++;
    }while (strtab[i][j] != '\0');
  }

  /*free our strtab*/
  for (int i = 0; i < elf_header->e_shnum; i++){
    free(strtab[i]);
  }
  free(strtab);

  if (abi_ndx == elf_header->e_shnum){
    printf("can't find abi section\n");
    goto close_all;
  }

  /*fill the corresponding section header*/
  map_to_sec_hdr(mapped, abi_ndx, elf_header, sec_header);
  sec_header->sh_type = SHT_PROGBITS;
  sec_header->sh_addr = virt_addr;
  sec_header->sh_offset = size;
  sec_header->sh_size = lseek(exec, 0, SEEK_END) - size;
  sec_header->sh_addralign = 16;
  sec_header->sh_flags |= SHF_EXECINSTR;

  /*rewrite the section header*/
  sec_hdr_to_map(mapped, abi_ndx, elf_header, sec_header);
  int64_t index = elf_header->e_shoff + abi_ndx * elf_header->e_shentsize;
  lseek(exec, index, SEEK_SET);
  if(write(exec, mapped+index, elf_header->e_shentsize) < 0){
    goto close_all;
  }


  /*REODER THE SECTION IN THE MAPPED FILE*/
  Elf64_Shdr * next_sec = malloc(sizeof(Elf64_Shdr));
  if (!next_sec){
    printf("error on malloc a third sec header\n");
    goto close_all;
  }
  
  /*get the direction to move*/
  map_to_sec_hdr(mapped, abi_ndx - 1, elf_header, next_sec);
  int sens = -1; /*need to swich left = 1 and right = -1*/
  if (next_sec->sh_addr < sec_header->sh_addr){
    sens = 1;
  }

  /*switch sections until they are reordered*/
  int n_shift = 0;
  for (int i = abi_ndx; 
       i <= elf_header->e_shnum && i >= 0;
       i += sens){
    map_to_sec_hdr(mapped, i, elf_header, sec_header);
    map_to_sec_hdr(mapped, i + sens, elf_header, next_sec);
    if ((int)((sec_header->sh_addr - next_sec->sh_addr) * sens) < 0 
        || next_sec->sh_addr == 0){
      break;
    }
    n_shift++;
    sec_hdr_to_map(mapped, i, elf_header, next_sec);
    sec_hdr_to_map(mapped, i + sens, elf_header, sec_header);
  }
  
  /*rewrite sh_links*/
  /*we reuse nextsec*/
  for (unsigned long i = abi_ndx; i != abi_ndx + n_shift * sens; i+= sens){
    map_to_sec_hdr(mapped, i, elf_header, next_sec);
    if (sens > 0 && next_sec->sh_link < abi_ndx + n_shift && next_sec->sh_link > abi_ndx){
      next_sec->sh_link--;
    }
    if (sens < 0 && next_sec->sh_link > abi_ndx + n_shift && next_sec->sh_link < abi_ndx){
      next_sec->sh_link++;
    }
    sec_hdr_to_map(mapped, i, elf_header, next_sec);
  }

  /*write this to the elf*/
  index = elf_header->e_shoff;
  lseek(exec, index, SEEK_SET);
  if(write(exec, mapped+index, elf_header->e_shentsize * elf_header->e_shnum) < 0){
    goto close_all;
  }

  /*free the tmp section header*/
  free(next_sec);
  
  /*check and adjust section name*/
  unsigned long good_len = strlen(".note.ABI-tag");
  if (strlen(arguments.args[2]) > good_len){
    arguments.args[2][good_len] = '\0';
  }
  
  /*change str in mapped file*/
  for (unsigned long i = 0; i < strlen(arguments.args[2]); i++){
    *(mapped + shstrtab->sh_offset + ndx_of_abi_in_strtab + i) = arguments.args[2][i];
  }
  for (unsigned long i = strlen(arguments.args[2]); i < good_len; i++){
    *(mapped + shstrtab->sh_offset + ndx_of_abi_in_strtab + i) = '.';
  }

  /*and write strtab changes in elf file*/
  index = shstrtab->sh_offset;
  lseek(exec, index, SEEK_SET);
  if(write(exec, mapped+index, shstrtab->sh_size) < 0){
    goto close_all;
  }

  /*modifying the PT_NOTE segment header*/
  prg_header->p_type = PT_LOAD;
  prg_header->p_offset = sec_header->sh_offset;
  prg_header->p_vaddr = sec_header->sh_addr;
  prg_header->p_paddr = sec_header->sh_addr;
  prg_header->p_filesz = sec_header->sh_size;
  prg_header->p_memsz = sec_header->sh_size;
  prg_header->p_flags |= PF_X;
  prg_header->p_align = 0x1000;

  /*write it to the map*/
  prg_hdr_to_map(mapped, pt_note_ndx, elf_header, prg_header);

  /*and to the executable*/
  index = elf_header->e_phoff;
  lseek(exec, index, SEEK_SET);
  if(write(exec, mapped+index, elf_header->e_phentsize * elf_header->e_phnum) < 0){
    goto close_all;
  }
 

  if (strtol(arguments.args[4], NULL, 10)){
    elf_header->e_entry = prg_header->p_vaddr;
  }

  /*write ir to the map*/
  elf_hdr_to_map(mapped, elf_header);
  /*and to the executable*/
  lseek(exec, 0, SEEK_SET);
  if(write(exec, mapped, elf_header->e_ehsize) < 0){
    goto close_all;
  }

  if (!strtol(arguments.args[4], NULL, 10)){
    mod_got_entry(mapped, got_int, prg_header->p_vaddr);
    lseek(exec, got_int, SEEK_SET);
    if(write(exec, mapped+got_int, sizeof(int64_t)) < 0){
      goto close_all;
    }
  }


close_all:
  if (mapped) {munmap(mapped, size);}
  if (exec != -1) {close(exec);}
  if (payload != -1) {close(payload);}
  if (prg_header) {free(prg_header);}
  if (elf_header) {free(elf_header);}
  if (shstrtab) {free(shstrtab);}
  if (sec_header) {free(sec_header);}


  return 0;

}

