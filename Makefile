CC = gcc
RM = rm
MKDIR = mkdir

EXT_WINDOWS = exe
EXT_LINUX   = out

# Can be either RELEASE or DEBUG
BUILD = RELEASE

SUFFIX_RELEASE =
SUFFIX_DEBUG   = _debug

# ------------------------------------------------------ #

TEST_CFILES        = tinyhttp.c tests/picohttpparser.c tests/test.c tests/test_reuse.c
TEST_HFILES        = tinyhttp.h tests/picohttpparser.h

TEST_FLAGS         = -Wall -Wextra
TEST_FLAGS_DEBUG   = -ggdb
TEST_FLAGS_RELEASE = -O2 -DNDEBUG

TEST_FLAGS_WINDOWS         = -lws2_32
TEST_FLAGS_WINDOWS_DEBUG   =
TEST_FLAGS_WINDOWS_RELEASE =

TEST_FLAGS_LINUX           =
TEST_FLAGS_LINUX_DEBUG     =
TEST_FLAGS_LINUX_RELEASE   =

# ------------------------------------------------------ #

DEMO0_CFILES            = tinyhttp.c examples/server_api.c
DEMO0_HFILES            = tinyhttp.h

DEMO0_FLAGS         =
DEMO0_FLAGS_DEBUG   = -ggdb
DEMO0_FLAGS_RELEASE = -O2 -DNDEBUG

DEMO0_FLAGS_WINDOWS         = -lws2_32
DEMO0_FLAGS_WINDOWS_DEBUG   =
DEMO0_FLAGS_WINDOWS_RELEASE =

DEMO0_FLAGS_LINUX           =
DEMO0_FLAGS_LINUX_DEBUG     =
DEMO0_FLAGS_LINUX_RELEASE   =

# ------------------------------------------------------ #

DEMO1_CFILES        = tinyhttp.c examples/stream_api_with_select.c
DEMO1_HFILES        = tinyhttp.h
DEMO1_FLAGS         =

DEMO1_FLAGS         =
DEMO1_FLAGS_DEBUG   = -ggdb
DEMO1_FLAGS_RELEASE = -O2 -DNDEBUG

DEMO1_FLAGS_WINDOWS         = -lws2_32
DEMO1_FLAGS_WINDOWS_DEBUG   =
DEMO1_FLAGS_WINDOWS_RELEASE =

DEMO1_FLAGS_LINUX           =
DEMO1_FLAGS_LINUX_DEBUG     =
DEMO1_FLAGS_LINUX_RELEASE   =

# ------------------------------------------------------ #
# ------------------------------------------------------ #
# ------------------------------------------------------ #

ifeq ($(OS),Windows_NT)
    OSTAG = WINDOWS
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        OSTAG = LINUX
    endif
    ifeq ($(UNAME_S),Darwin)
        OSTAG = OSX
    endif
endif

EXT = ${EXT_$(OSTAG)}

TEST_FLAGS += ${TEST_FLAGS_$(BUILD)}
TEST_FLAGS += ${TEST_FLAGS_$(OSTAG)}
TEST_FLAGS += ${TEST_FLAGS_$(OSTAG)_$(BUILD)}

DEMO0_FLAGS += ${DEMO0_FLAGS_$(BUILD)}
DEMO0_FLAGS += ${DEMO0_FLAGS_$(OSTAG)}
DEMO0_FLAGS += ${DEMO0_FLAGS_$(OSTAG)_$(BUILD)}

DEMO1_FLAGS += ${DEMO1_FLAGS_$(BUILD)}
DEMO1_FLAGS += ${DEMO1_FLAGS_$(OSTAG)}
DEMO1_FLAGS += ${DEMO1_FLAGS_$(OSTAG)_$(BUILD)}

SUFFIX = ${SUFFIX_$(BUILD)}

# ------------------------------------------------------ #
# ------------------------------------------------------ #
# ------------------------------------------------------ #

.PHONY: all clean

all: out/test$(SUFFIX).$(EXT) out/demo0$(SUFFIX).$(EXT) out/demo1$(SUFFIX).$(EXT)

out:
	$(MKDIR) out

out/test$(SUFFIX).$(EXT): out $(TEST_CFILES) $(TEST_HFILES)
	$(CC) -o $@ $(TEST_CFILES) $(TEST_FLAGS)

out/demo0$(SUFFIX).$(EXT): out $(DEMO0_CFILES) $(DEMO0_HFILES)
	$(CC) -o $@ $(DEMO0_CFILES) $(DEMO0_FLAGS)

out/demo1$(SUFFIX).$(EXT): out $(DEMO1_CFILES) $(DEMO1_HFILES)
	$(CC) -o $@ $(DEMO1_CFILES) $(DEMO1_FLAGS)

clean:
	$(RM) -fr out
