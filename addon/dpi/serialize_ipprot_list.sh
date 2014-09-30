#!/bin/bash
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

echo -e "\nvar IPProtocols = map[int] string {"
egrep -v "^#" /etc/protocols | awk '{if($2 != "" && $1 != "ip"){ print "  " $2 ": \"" $3 "\","} }'
echo -e "  255: \"UNKNOWN\",\n}\n\nfunc GetIPProto(id int) string {\n  return IPProtocols[id]\n}\n"

echo -e "\nvar IPProtocolIDs = map[string] int {"
egrep -v "^#" /etc/protocols | grep -v "for experimentation and testing" | awk '{if( $2 != "" && $1 != "ip"){ print "  \"" $3 "\": " $2 ","}}'
echo -e "  \"UNKNOWN\": 255,\n}\n\nfunc GetIPProtoID(name string) (uint64, bool) {\n  ret, ok := IPProtocolIDs[name]\n  return uint64(ret), ok\n}\n"

exit 0
