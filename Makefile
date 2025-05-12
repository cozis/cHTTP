.PHONY: all report

OSTAG = LINUX
#OSTAG = WINDOWS

EXT_WINDOWS = .exe
EXT_LINUX   = .out

LFLAGS_WINDOWS = -lws2_32
LFLAGS_LINUX   = -lssl -lcrypto -ggdb

LFLAGS = ${LFLAGS_${OSTAG}}
EXT = ${EXT_${OSTAG}}

all:
	gcc -o test$(EXT) tests/test.c tests/test_branch_coverage_parse.c tests/test_branch_coverage_engine.c tests/test_fuzz_engine.c tinyhttp.c -fprofile-arcs -ftest-coverage $(LFLAGS)

report:
	lcov --capture --directory . --output-file coverage.info --rc lcov_branch_coverage=1
	genhtml coverage.info --output-directory coverage_report --rc lcov_branch_coverage=1 --rc genhtml_branch_coverage=1

clean:
	rm *.gcda *.gcno coverage.info test$(EXT_WINDOWS) test$(EXT_LINUX)
