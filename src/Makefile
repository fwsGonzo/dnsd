######################
#   dnsd  makefile   #
######################

# (2) select build options
# Fast:
# -Ofast -msse4.1 -ffast-math -mfpmath=both -march=native
# Debug:
# -ggdb3
BUILDOPT = -ggdb3 -march=native
# output file
OUTPUT   = ./test

##############################################################

# code folders
FILES = main.cpp dns.cpp

# compiler
CC = g++ $(BUILDOPT) -std=c++11
# compiler flags
CCFLAGS = -c -MMD -Wall -Wextra -Wno-write-strings -Iinc -Iinclude
# linker flags
LDFLAGS = -Llib

##############################################################

# make pipeline
CCDIRS  = $(foreach dir, $(SOURCE_DIRS), $(dir)/*.c)
CCMODS  = $(wildcard $(CCDIRS))
CXXMODS = $(FILES)

# compile each .c to .o
.c.o:
	$(CC) $(CCFLAGS) $< -o $@

# compile each .cpp to .o
.cpp.o:
	$(CC) $(CCFLAGS) $< -o $@

# convert .c to .o
CCOBJS  = $(CCMODS:.c=.o)
# convert .cpp to .o
CXXOBJS = $(CXXMODS:.cpp=.o)
# convert .o to .d
DEPENDS = $(CXXOBJS:.o=.d) $(CCOBJS:.o=.d)

.PHONY: all clean

# link all OBJS using CC and link with LFLAGS, then output to OUTPUT
all: $(CXXOBJS) $(CCOBJS)
	$(CC) $(CXXOBJS) $(CCOBJS) $(LDFLAGS) -o $(OUTPUT)

# remove each known .o file, and output
clean:
	$(RM) $(CXXOBJS) $(CCOBJS) $(DEPENDS) $(OUTPUT)

-include $(DEPENDS)
