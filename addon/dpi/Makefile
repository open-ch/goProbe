# This code has been developed by Open Systems AG
#
# goProbe is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# goProbe is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with goProbe; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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

