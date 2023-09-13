CFLAGS= -O2 -Warray-bounds -g -Wsequence-point -Walloc-zero -Wnull-dereference -Wpointer-arith -Wcast-qual -Wcast-align=strict -fanalyzer
LDFLAGS= -lbfd
CPPFLAGS= -I../includes -I.

$(MAKECMDGOALS):
	bear -- make $@

all : isos_inject clang_tidy isos_inject-c1 isos_inject-c2 isos_inject-c3 isos_inject-c4 isos_inject-c5 payload

payload : payload.s
	nasm -f bin payload.s -o payload

clang_tidy :
	clang-tidy -checks=cert-*,-clang-analyzer-* isos_inject.c elf_parse.c init.c

isos_inject-c1:
	clang -fsyntax-only -Wall -Wextra -Wuninitialized -Wpointer-arith -Wcast-qual -Wcast-align -I ../includes isos_inject.c

isos_inject-c2 :
	clang -fsanitize=address -fsanitize=alignment -fsanitize=bool -fsanitize=bounds -fsanitize=builtin -fsanitize=enum -fsanitize=float-cast-overflow -fsanitize=float-divide-by-zero -fsanitize=integer-divide-by-zero -fsanitize=nonnull-attribute -fsanitize=null -fsanitize=object-size -fsanitize=pointer-compare -fsanitize=pointer-overflow -fsanitize=pointer-subtract -fsanitize=return -fsanitize=returns-nonnull-attribute -fsanitize=shadow-call-stack -fsanitize=shift -fsanitize=shift-base -fsanitize=shift-exponent -fsanitize=signed-integer-overflow -fsanitize=undefined -fsanitize=unreachable -fsanitize=vla-bound -fsanitize=vptr -O2 -o clang1 -I ../includes isos_inject.c elf_parse.c init.c $(LDFLAGS)

isos_inject-c3 :
	clang -fsanitize=thread -o clang2 -I ../includes isos_inject.c elf_parse.c init.c $(LDFLAGS)

isos_inject-c4 :
	clang  -fsanitize=leak -o clang3 -I ../includes isos_inject.c elf_parse.c init.c $(LDFLAGS)

isos_inject-c5 :
	clang -fsanitize=memory -o clang4 -I ../includes isos_inject.c elf_parse.c init.c $(LDFLAGS)

isos_inject : isos_inject.o init.o elf_parse.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

isos_inject.o : isos_inject.c ../includes/init.h ../includes/elf_parse.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<

init.o : init.c ../includes/init.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<

elf_parse.o : elf_parse.c ../includes/elf_parse.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<


clean :
	@rm -f *.o isos_inject && rm -f clang* && rm payload

.PHONY = all clean