SRCDIR := src
DEPDIR := dependencies
INCDIR := includes
LIBDIR := libs
OBJDIR := obj

SRCS   := $(wildcard $(SRCDIR)/*.cpp)
OBJS   := $(patsubst $(SRCDIR)/%.cpp, $(OBJDIR)/%.o, $(SRCS))
LIBS   := $(wildcard $(LIBDIR)/*.a)

CC := g++
CCFLAGS := -std=c++11 -flto -I$(INCDIR) -I$(DEPDIR)/asio -I$(DEPDIR)/protobuf

TARGET := zynq-updater

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -flto $(LIBS) $^ -o $@

# | OBJDIR does not affect $^
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(CC) $(CCFLAGS) -c $< -o $@

# If OBJDIR doesn't exist, create it
$(OBJDIR):
	mkdir -p $@

clean:
	rm $(OBJDIR)/*.o

.PHONY: all clean
