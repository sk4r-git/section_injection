#include <argp.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <bfd.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/mman.h>


int16_t fill_16(unsigned char *map, int index){
    int16_t buffer = 0;
    buffer = *(map + index + 1);
    buffer <<= 8;
    buffer += *(map + index);
    return buffer;
}

int32_t fill_32(unsigned char *map, int index){
    int32_t buffer = 0;
    buffer = *(map + index + 3);
    buffer <<= 8;
    buffer += *(map + index + 2);
    buffer <<= 8;
    buffer += *(map + index + 1);
    buffer <<= 8;
    buffer += *(map + index);
    return buffer;
}


int64_t fill_64(unsigned char *map, int index){
    int64_t buffer = 0;
    buffer = *(map + index + 7);
    buffer <<= 8;
    buffer += *(map + index + 6);
    buffer <<= 8;
    buffer += *(map + index + 5);
    buffer <<= 8;
    buffer += *(map + index + 4);
    buffer <<= 8;
    buffer += *(map + index + 3);
    buffer <<= 8;
    buffer += *(map + index + 2);
    buffer <<= 8;
    buffer += *(map + index + 1);
    buffer <<= 8;
    buffer += *(map + index);
    return buffer;
}


void write_16(unsigned char *map, int index, int32_t buf){
  *(map + index )    = (unsigned char) ((buf << 8) >> 8);
  *(map + index + 1) = (unsigned char) (buf >> 8);
  return;
}


void write_32(unsigned char *map, int index, int32_t buf){
  *(map + index )    = (unsigned char) ((buf << 24) >> 24);
  *(map + index + 1) = (unsigned char) ((buf << 16) >> 24);
  *(map + index + 2) = (unsigned char) ((buf << 8) >> 24);
  *(map + index + 3) = (unsigned char) (buf >> 24);
  return;
}


void write_64(unsigned char *map, int index, int64_t buf){
  *(map + index )    = (unsigned char) ( buf % 0x100);
  *(map + index + 1) = (unsigned char) ((buf >> 8) % 0x100);
  *(map + index + 2) = (unsigned char) ((buf >> 16) % 0x100);
  *(map + index + 3) = (unsigned char) ((buf >> 24) % 0x100);
  *(map + index + 4) = (unsigned char) ((buf >> 32) % 0x100);
  *(map + index + 5) = (unsigned char) ((buf >> 40) % 0x100);
  *(map + index + 6) = (unsigned char) ((buf >> 48 ) % 0x100);
  *(map + index + 7) = (unsigned char) ((buf >> 56));
  return;
}



void map_to_elf_hdr(unsigned char * map, Elf64_Ehdr * elf_header){
  for (int i = 0; i < 16; i++){
    elf_header->e_ident[i] = *(map + i);
  }
  elf_header->e_type = fill_16(map, 16);
  elf_header->e_machine = fill_16(map, 18);
  elf_header->e_version = fill_32(map, 20);
  elf_header->e_entry = fill_64(map, 24);
  elf_header->e_phoff = fill_64(map, 32);
  elf_header->e_shoff = fill_64(map, 40);
  elf_header->e_flags = fill_32(map, 48);
  elf_header->e_ehsize = fill_16(map, 52);
  elf_header->e_phentsize = fill_16(map, 54);
  elf_header->e_phnum = fill_16(map, 56);
  elf_header->e_shentsize = fill_16(map, 58);
  elf_header->e_shnum = fill_16(map, 60);
  elf_header->e_shstrndx = fill_16(map, 62);
  return;
}

void display_elf_hdr(Elf64_Ehdr * elf_header){
  printf("ELF header : \n");
  printf("e_indent : %s\n", elf_header->e_ident);
  printf("e_type : %d\n", elf_header->e_type);
  printf("e_machine : %d\n", elf_header->e_machine);
  printf("e_version : %d\n", elf_header->e_version);
  printf("e_entry : %lu\n", elf_header->e_entry);
  printf("e_phoff : %lu\n", elf_header->e_phoff);
  printf("e_shoff : %lu\n", elf_header->e_shoff);
  printf("e_flags : %d\n", elf_header->e_flags);
  printf("e_ehsize : %d\n", elf_header->e_ehsize);
  printf("e_phentsize : %d\n", elf_header->e_phentsize);
  printf("e_phnum : %d\n", elf_header->e_phnum);
  printf("e_shentsize : %d\n", elf_header->e_shentsize);
  printf("e_shnum : %d\n", elf_header->e_shnum);
  printf("e_shstrndx : %d\n\n", elf_header->e_shstrndx);
  return;
}

void map_to_prg_hdr(unsigned char * map, int num, 
                    Elf64_Ehdr * elf_header, Elf64_Phdr * prg_header){
  int64_t index = elf_header->e_phoff + num * elf_header->e_phentsize;
  prg_header->p_type = fill_32(map, index);
  prg_header->p_flags = fill_32(map, index + 4);
  prg_header->p_offset = fill_64(map, index + 8);
  prg_header->p_vaddr = fill_64(map, index + 16);
  prg_header->p_paddr = fill_64(map, index + 24);
  prg_header->p_filesz = fill_64(map, index + 32);
  prg_header->p_memsz = fill_64(map, index + 40);
  prg_header->p_align = fill_64(map, index + 48);
  return;
}

void display_prg_header(Elf64_Phdr * prg_header){
  printf("Segment header : \n");
  printf("p_type : %d\n", prg_header->p_type);
  printf("p_flags : %d\n", prg_header->p_flags);
  printf("p_offset : %ld\n", prg_header->p_offset);
  printf("p_vaddr : %ld\n", prg_header->p_vaddr);
  printf("p_paddr : %ld\n", prg_header->p_paddr);
  printf("p_filesz : %ld\n", prg_header->p_filesz);
  printf("p_memsz : %ld\n", prg_header->p_memsz);
  printf("p_align : %ld\n\n", prg_header->p_align);
  return;
}

void map_to_sec_hdr(unsigned char * map, int num, 
                    Elf64_Ehdr * elf_hdr, Elf64_Shdr * sec_hdr){
  int64_t index = elf_hdr->e_shoff + num * elf_hdr->e_shentsize;
  sec_hdr->sh_name = fill_32(map, index);
  sec_hdr->sh_type = fill_32(map, index + 4);
  sec_hdr->sh_flags = fill_64(map, index + 8);
  sec_hdr->sh_addr = fill_64(map, index + 16);
  sec_hdr->sh_offset = fill_64(map, index + 24);
  sec_hdr->sh_size = fill_64(map, index + 32);
  sec_hdr->sh_link = fill_32(map, index + 40);
  sec_hdr->sh_info = fill_32(map, index + 44);
  sec_hdr->sh_addralign = fill_64(map, index + 48);
  sec_hdr->sh_entsize = fill_64(map, index + 56);
  return;
}

void display_sec_hdr(Elf64_Shdr * sec_hdr){
  printf("Section header : \n");
  printf("sh_name : %d\n", sec_hdr->sh_name);
  printf("sh_type : %d\n", sec_hdr->sh_type);
  printf("sh_flags : %ld\n", sec_hdr->sh_flags);
  printf("sh_addr : %ld\n", sec_hdr->sh_addr);
  printf("sh_offset : %ld\n", sec_hdr->sh_offset);
  printf("sh_size : %ld\n", sec_hdr->sh_size);
  printf("sh_link : %d\n", sec_hdr->sh_link);
  printf("sh_info : %d\n", sec_hdr->sh_info);
  printf("sh_addralign : %ld\n", sec_hdr->sh_addralign);
  printf("sh_entsize : %ld\n\n", sec_hdr->sh_entsize);
  return;
}

void sec_hdr_to_map(unsigned char * map, int num, 
                    Elf64_Ehdr * elf_hdr, Elf64_Shdr * sec_hdr){
  int64_t index = elf_hdr->e_shoff + num * elf_hdr->e_shentsize;
  write_32(map, index, sec_hdr->sh_name);
  write_32(map, index + 4, sec_hdr->sh_type);
  write_64(map, index + 8, sec_hdr->sh_flags);
  write_64(map, index + 16, sec_hdr->sh_addr);
  write_64(map, index + 24, sec_hdr->sh_offset);
  write_64(map, index + 32, sec_hdr->sh_size);
  write_32(map, index + 40, sec_hdr->sh_link);
  write_32(map, index + 44, sec_hdr->sh_info);
  write_64(map, index + 48, sec_hdr->sh_addralign);
  write_64(map, index + 56, sec_hdr->sh_entsize);
  return;
}

void prg_hdr_to_map(unsigned char * map, int num,
                    Elf64_Ehdr * elf_hdr, Elf64_Phdr * prg_header){
  int64_t index = elf_hdr->e_phoff + num * elf_hdr->e_phentsize;
  write_32(map, index, prg_header->p_type);
  write_32(map, index + 4, prg_header->p_flags);
  write_64(map, index + 8, prg_header->p_offset);
  write_64(map, index + 16, prg_header->p_vaddr);
  write_64(map, index + 24, prg_header->p_paddr);
  write_64(map, index + 32, prg_header->p_filesz);
  write_64(map, index + 40, prg_header->p_memsz);
  write_64(map, index + 48, prg_header->p_align);
  return;
}

void elf_hdr_to_map(unsigned char * map,
                    Elf64_Ehdr * elf_header){
  for (int i = 0; i < 16; i++){
    *(map + i) = elf_header->e_ident[i];
  }
  write_16(map, 16, elf_header->e_type);
  write_16(map, 18, elf_header->e_machine);
  write_32(map, 20, elf_header->e_version);
  write_64(map, 24, elf_header->e_entry);
  write_64(map, 32, elf_header->e_phoff);
  write_64(map, 40, elf_header->e_shoff);
  write_32(map, 48, elf_header->e_flags);
  write_16(map, 52, elf_header->e_ehsize);
  write_16(map, 54, elf_header->e_phentsize);
  write_16(map, 56, elf_header->e_phnum);
  write_16(map, 58, elf_header->e_shentsize);
  write_16(map, 60, elf_header->e_shnum);
  write_16(map, 62, elf_header->e_shstrndx);
  return;
}

void mod_got_entry(unsigned char * map, int64_t ndx,
                   int64_t to_write){
  write_64(map, ndx, to_write);
  return;
}