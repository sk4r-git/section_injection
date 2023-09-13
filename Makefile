all : 
	@cd src && $(MAKE)
	@cp -f src/isos_inject ./ && cp -f src/payload ./

test :
	@xxd ./includes/date > ./hexdate.txt
	@xxd ./date > ./hexmoddate.txt
	@diff --suppress-common-lines ./hexmoddate.txt ./hexdate.txt > ./diffdate.txt
	
clang_test :
	@rm ./date
	@cp ./includes/date ./date
	@./src/clang1 ./date payload .sec 1 1
	@rm ./date
	@cp ./includes/date ./date
	@./src/clang2 ./date payload .sec 1 1
	@rm ./date
	@cp ./includes/date ./date
	@./src/clang3 ./date payload .sec 1 1
	@rm ./date
	@cp ./includes/date ./date
	@./src/clang4 ./date payload .sec 1 1

clean :
	@rm -f date
	@cp -f includes/date ./
	@cd src && $(MAKE) clean
	@rm -f isos_inject && rm -f payload
	@rm ./diffdate.txt ./hexdate.txt ./hexmoddate.txt
	
.PHONY = all clean test