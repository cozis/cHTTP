.PHONY: all report

#LFLAGS = -lws2_32
LFLAGS = -lssl -lcrypto -ggdb

all:
	#gcc -o test tests/test.c tests/test_branch_coverage.c http.c -fprofile-arcs -ftest-coverage

report:
	lcov --capture --directory . --output-file coverage.info --rc lcov_branch_coverage=1
	genhtml coverage.info --output-directory coverage_report --rc lcov_branch_coverage=1 --rc genhtml_branch_coverage=1

clean:
	rm *.gcda *.gcno coverage.info test test.exe
