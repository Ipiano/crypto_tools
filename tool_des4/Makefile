# General variables
CC = g++
CFLAGS += --std=c++11
LIBS += -lm -L$(LIBS_DIR)

TARGET = tool_des4

PROJECT_ROOT = $(PWD)/..
CRYPTO_ROOT = $(PROJECT_ROOT)/modules/module_crypto
CRYPTO_LIBS = des

BUILD_TYPE ?= release
BUILD_DIR = $(PROJECT_ROOT)/build/$(BUILD_TYPE)
OBJECTS_DIR = $(BUILD_DIR)/objects
LIBS_DIR = $(BUILD_DIR)/lib
DEST_DIR = $(PWD)/$(BUILD_TYPE)

all: $(if $(findstring debug, $(BUILD_TYPE)),\
		$(info Debug Build) \
			$(eval CFLAGS += -g) \
			$(eval DEFINES += -DDEBUG), \
		$(info Release Build) \
			$(eval CFLAGS += -O2))
all: $(TARGET)

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
	@-rm $(OBJECTS_DIR)/*.o 2>/dev/null || true
	@-rm $(LIBS_DIR)/*.a 2>/dev/null || true
	@-rm $(DEST_DIR)/$(TARGET) 2>/dev/null || true

objs_main = $(patsubst %.o, $(OBJECTS_DIR)/%.o, main.o)
build_objects = $(objs_main) $(LIB_OBJECTS)

# Substitute objects location onto object files from internal libs
$(TARGET): $(build_objects) | mkdirs
	$(CC) $(build_objects) $(LIBS) -o $(DEST_DIR)/$@

.FORCE:
$(objs_main): $(OBJECTS_DIR)/%.o: src/%.cpp $(LIB_HEADERS) .FORCE
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) $< -o $@