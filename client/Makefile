SRCDIR := src
DEPDIR := dependencies
INCDIR := includes
LIBDIR := libs
OBJDIR := obj

SRCS   := $(wildcard $(SRCDIR)/*.cpp)
OBJS   := $(patsubst $(SRCDIR)/%.cpp, $(OBJDIR)/%.o, $(SRCS))
LIBS   := $(wildcard $(LIBDIR)/*.a)

CC := g++
CCFLAGS := -Wall -std=c++11 -I$(INCDIR) -I$(DEPDIR)/asio/asio/include -I$(DEPDIR)/protobuf

TARGET := zynq-updater

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LIBS) $^ -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(CC) $(CCFLAGS) -c $< -o $@

# If OBJDIR doesn't exist, create it
$(OBJDIR):
	mkdir -p $@

clean:
	rm $(OBJDIR)/*.o

.PHONY: all clean
