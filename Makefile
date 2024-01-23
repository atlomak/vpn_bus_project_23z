# Define the C compiler to use
CC = gcc

# Define any compile-time flags
CFLAGS := -Wall -Wextra -g

# Define library paths in addition to /usr/lib
LFLAGS = -lssl -lcrypto

# Define output directory
OUTPUT := output

# Define source directories
CLIENT_SRC := src/client
SERVER_SRC := src/server
SHARED_SRC := src/shared

# Define include directory
INCLUDE := include

# Define lib directory
LIB := lib

# Executable names
CLIENT := $(OUTPUT)/client
SERVER := $(OUTPUT)/server

# Platform-specific settings
ifeq ($(OS),Windows_NT)
    FIXPATH = $(subst /,\,$1)
    RM := del /q /f
    MD := mkdir
else
    FIXPATH = $1
    RM = rm -f
    MD := mkdir -p
endif

# Directories containing header files other than /usr/include
INCLUDES := $(patsubst %,-I%, $(INCLUDE:%/=%))

# C library paths
LIBS := $(patsubst %,-L%, $(LIB:%/=%))

# Define the C source files
CLIENT_SOURCES := $(wildcard $(CLIENT_SRC)/*.c) $(wildcard $(SHARED_SRC)/*.c)
SERVER_SOURCES := $(wildcard $(SERVER_SRC)/*.c) $(wildcard $(SHARED_SRC)/*.c)

# Define the C object files 
CLIENT_OBJECTS := $(CLIENT_SOURCES:.c=.o)
SERVER_OBJECTS := $(SERVER_SOURCES:.c=.o)

# Define the dependency output files
CLIENT_DEPS := $(CLIENT_OBJECTS:.o=.d)
SERVER_DEPS := $(SERVER_OBJECTS:.o=.d)

# The following part of the makefile is generic; it can be used to 
# build any executable just by changing the definitions above and by
# deleting dependencies appended to the file from 'make depend'
#

all: $(OUTPUT) $(CLIENT) $(SERVER)
	@echo Executing 'all' complete!

$(OUTPUT):
	$(MD) $(OUTPUT)

$(CLIENT): $(CLIENT_OBJECTS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(CLIENT) $(CLIENT_OBJECTS) $(LFLAGS) $(LIBS)

$(SERVER): $(SERVER_OBJECTS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(SERVER) $(SERVER_OBJECTS) $(LFLAGS) $(LIBS)

# Include all .d files
-include $(CLIENT_DEPS) $(SERVER_DEPS)

# This is a suffix replacement rule for building .o's and .d's from .c's
.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -MMD $< -o $@

.PHONY: clean
clean:
	$(RM) $(CLIENT) $(SERVER)
	$(RM) $(call FIXPATH,$(CLIENT_OBJECTS) $(SERVER_OBJECTS))
	$(RM) $(call FIXPATH,$(CLIENT_DEPS) $(SERVER_DEPS))
	@echo Cleanup complete!

run: all
	@echo "Run your executables manually (./$(CLIENT) or ./$(SERVER))"