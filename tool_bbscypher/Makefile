# General variables
CC = g++
CFLAGS += --std=c++11 -O1
LIBS += -lm -lpthread -L$(LIBS_DIR)

PROJECT_ROOT = $(PWD)/..
CRYPTO_ROOT = $(PROJECT_ROOT)/modules/module_crypto
CRYPTO_LIBS = random
LIBRANDOM_FEATURES = bbs

BUILD_TYPE = release
BUILD_DIR = $(PROJECT_ROOT)/build/$(BUILD_TYPE)
OBJECTS_DIR = $(BUILD_DIR)/objects
LIBS_DIR = $(BUILD_DIR)/lib
DEST_DIR = $(PWD)/$(BUILD_TYPE)

# Build debug mode by default
# Change all output directories
debug: CFLAGS += -g
debug: BUILD_TYPE = debug
debug: release

release: tool_bbscypher

# Include necessary headers and either sources or libraries
include $(CRYPTO_ROOT)/include.mk

# Newline in terminal output
$(info   )

.PHONY: clean mkdirs

mkdirs:
	@-mkdir -p $(BUILD_DIR)
	@-mkdir -p $(OBJECTS_DIR)
	@-mkdir -p $(LIBS_DIR)
	@-mkdir -p $(DEST_DIR)

clean:
	rm $(PWD)/*.o
	rm $(OBJECTS_DIR)/*.o


objs_main = main.o

# Substitute objects location onto object files from internal libs
tool_bbscypher: build_objects = $(patsubst %.o, $(OBJECTS_DIR)/%.o, $(objs_main) $(LIB_OBJECTS))
tool_bbscypher: mkdirs $(objs_main) $(INCLUDED_LIBS)
	$(CC) $(build_objects) $(LIBS) -o $(DEST_DIR)/$@

$(objs_main): %.o: src/%.cpp
	$(CC) -c $(CFLAGS) $(INCLUDES) $^ -o $(OBJECTS_DIR)/$@