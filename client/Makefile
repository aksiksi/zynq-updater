SRCDIR := src
DEPDIR := dependencies
INCDIR := includes
LIBDIR := libs
OBJDIR := obj

SRCS   := $(wildcard $(SRCDIR)/*.cpp)
OBJS   := $(patsubst $(SRCDIR)/%.cpp, $(OBJDIR)/%.o, $(SRCS))
LIBS   := $(wildcard $(LIBDIR)/*.a)

ASIO_DIR := $(DEPDIR)/asio/asio/include
PROTOBUF_DIR := $(DEPDIR)/protobuf/src

CC := arm-linux-gnueabihf-g++
CCFLAGS  := -Wall -std=c++11
INCLUDES := -I$(INCDIR) -I$(ASIO_DIR) -I$(PROTOBUF_DIR)
LIBS := -L $(LIBDIR) -l protobuf -l pthread

TARGET := zynq-updater

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $^ $(LIBS) -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(CC) $(CCFLAGS) $(INCLUDES) -c $< -o $@

# If OBJDIR doesn't exist, create it
$(OBJDIR):
	mkdir -p $@

clean:
	rm $(OBJDIR)/*.o

.PHONY: all clean
