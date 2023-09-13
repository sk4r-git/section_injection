all : 
	@cd src && $(MAKE)
	@cp -f src/isos_inject ./ && cp -f src/payload_ep ./ && cp -f src/payload_got ./
	@cp -f includes/date ./

clang_test_1_got :
	@rm ./date
	@cp ./includes/date ./date
	@./src/clang1 ./date payload_got .sec 8388608 0
	@./date
clang_test_2_got :
	@rm ./date
	@cp ./includes/date ./date
	@./src/clang2 ./date payload_got .sec 8388608 0
	@./date
clang_test_3_got :
	@rm ./date
	@cp ./includes/date ./date
	@./src/clang3 ./date payload_got .sec 8388608 0
	@./date
clang_test_4_got :
	@rm ./date
	@cp ./includes/date ./date
	@./src/clang4 ./date payload_got .sec 8388608 0
	@./date
clang_test_1_entry :
	@rm ./date
	@cp ./includes/date ./date
	@./src/clang1 ./date payload_ep .sec 8388608 1
	@./date
	@cp ./src/payload_ep ./
clang_test_2_entry :
	@rm ./date
	@cp ./includes/date ./date
	@./src/clang2 ./date payload_ep .sec 8388608 1
	@./date
	@cp ./src/payload_ep ./
clang_test_3_entry :
	@rm ./date
	@cp ./includes/date ./date
	@./src/clang3 ./date payload_ep .sec 8388608 1
	@./date
	@cp ./src/payload_ep ./
clang_test_4_entry :
	@rm ./date
	@cp ./includes/date ./date
	@./src/clang4 ./date payload_ep .sec 8388608 1
	@./date
	@cp ./src/payload_ep ./

clean :
	@rm -f date
	@cp -f includes/date ./
	@cd src && $(MAKE) clean
	@rm -f isos_inject && rm -f payload_ep payload_got
	@rm -f ./date ./src/date
	
.PHONY = all clean