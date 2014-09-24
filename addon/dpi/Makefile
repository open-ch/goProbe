PROGRAM      = ProtoId
SERIALIZER   = serialize_prot_list

# Programs
CXX          = g++
CXXFLAGS     = -Wall -Wextra -Wno-deprecated -fPIC -O2 #-pg -ggdb
LD           = g++
LDFLAGS      = -O2 -shared -pthread #-pg -ggdb

RM           = rm -f 
MV           = mv 
ECHO         = echo

# Assign or Add libraries
CXXFLAGS    += -I../../libprotoident-2.0.7/lib -I../../libtrace-3.0.20/lib
LIBS        += -L../../libprotoident-2.0.7/lib/.libs -L../../libtrace-3.0.20/lib/.libs -lprotoident -ltrace

CXXSRCS      = $(PROGRAM).cxx

GARBAGE      = $(PROGRAM).so $(PROGRAM).o lib$(PROGRAM).so

all :   $(PROGRAM)

clean :
	$(RM) $(GARBAGE)

$(PROGRAM) :
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(PROGRAM).cxx    $(LIBS) -o lib$(PROGRAM).so
	$(CXX) $(CXXFLAGS)            $(SERIALIZER).cxx $(LIBS) -o $(SERIALIZER)

print :
	echo compiler  : $(CXX)
	echo compiler  : $(CXSRCS)
	echo c++ srcs  : $(CXXSRCS)
	echo c++ objs  : $(CXXOBJS)
	echo c++ flags : $(CXXFLAGS)
	echo libs      : $(LIBS)
	echo so flags  : $(SOFLAGS)

