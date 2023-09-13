#include <argp.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <bfd.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/mman.h>

/*parse elf header of the mapped file*/
void map_to_elf_hdr(unsigned char * map, Elf64_Ehdr * elf_header);

/*rewrite section header number 'num' to the mapped file*/
void elf_hdr_to_map(unsigned char * map,
                    Elf64_Ehdr * elf_header);

void display_elf_hdr(Elf64_Ehdr * elf_header);



/*parse segment header number 'num'*/
void map_to_prg_hdr(unsigned char * map, int num, 
                    Elf64_Ehdr * elf_header, Elf64_Phdr * prg_header);

/*rewrite program header number 'num' to the mapped file*/
void prg_hdr_to_map(unsigned char * map, int num,
                    Elf64_Ehdr * elf_hdr, Elf64_Phdr * prg_header);

void display_prg_header(Elf64_Phdr * prg_header);



/*parse section header number 'num'*/
void map_to_sec_hdr(unsigned char * map, int num, 
                    Elf64_Ehdr * elf_hdr, Elf64_Shdr * sec_hdr);

/*rewrite section header number 'num' to the mapped file*/
void sec_hdr_to_map(unsigned char * map, int num, 
                    Elf64_Ehdr * elf_hdr, Elf64_Shdr * sec_hdr);

void display_sec_hdr(Elf64_Shdr * sec_hdr);



/*modifie the got entry for getenv@plt*/
void mod_got_entry(unsigned char * map, int64_t ndx,
                   int64_t to_write);