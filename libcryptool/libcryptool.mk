# Define path to this lib
pwd_cryptool := $(PROJECT_ROOT)/libcryptool
$(info Including cryptool additions at $(pwd_cryptool))

# Set up object files for this lib
objs_cryptool = cryptooltest.o
LIB_OBJECTS += $(objs_cryptool)
INCLUDED_LIBS += cryptool
INCLUDES += -I$(pwd_cryptool)/headers

# Define recipe for this build
cryptool: $(objs_cryptool)

# Define recipes for objects in this lib
$(objs_cryptool): %.o: $(pwd_cryptool)/src/%.cpp
	$(CC) -c $(CFLAGS) $(INCLUDES) $^ -o $(OBJECTS_DIR)/$@