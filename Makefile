# Makefile for tinyhttp with cross-platform support
# Supports Windows and Linux with various build configurations

# Detect operating system
ifeq ($(OS),Windows_NT)
    DETECTED_OS := Windows
    # On Windows, we need to link with winsock library
    LIBS := -lws2_32
    RM := del /Q
    # Windows executable extension
    EXE := .exe
else
    DETECTED_OS := $(shell uname -s)
    LIBS :=
    RM := rm -f
    EXE :=
endif

# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -I.
LDFLAGS :=

# Project files
SRC := tinyhttp.c example.c
HEADERS := tinyhttp.h
TARGET := example$(EXE)

# Default target
.PHONY: all clean release debug asan coverage

# Default is release build
all: release

# Release build
release: CFLAGS += -O2 -DNDEBUG
release: $(TARGET)

# Debug build
debug: CFLAGS += -ggdb -DDEBUG
debug: $(TARGET)

# Address Sanitizer build
asan: CFLAGS += -fsanitize=address -fno-omit-frame-pointer -O1
asan: LDFLAGS += -fsanitize=address
asan: $(TARGET)

# Coverage build
coverage: CFLAGS += -fprofile-arcs -ftest-coverage -O0
coverage: LDFLAGS += -fprofile-arcs -ftest-coverage
coverage: $(TARGET)

# Compile and link
$(TARGET): $(SRC) $(HEADERS)
	$(CC) $(CFLAGS) $(SRC) -o $@ $(LDFLAGS) $(LIBS)

# Clean build artifacts
clean:
ifeq ($(DETECTED_OS),Windows)
	$(RM) $(TARGET) *.gcda *.gcno *.gcov
else
	$(RM) $(TARGET) *.o *.gcda *.gcno *.gcov
endif

# Show help
help:
	@echo "Available targets:"
	@echo "  all      - Same as 'release'"
	@echo "  release  - Optimized build (-O2, NDEBUG)"
	@echo "  debug    - Debug build with symbols (-ggdb)"
	@echo "  asan     - Address Sanitizer build"
	@echo "  coverage - Code coverage build"
	@echo "  clean    - Remove build artifacts"
	@echo "  help     - Show this help"