#!/bin/bash

echo -e "\nvar IPProtocols = map[int] string {"
egrep -v "^#" /etc/protocols | awk '{if($2 != "" && $1 != "ip"){ print "  " $2 ": \"" $3 "\","} }'
echo -e "  255: \"UNKNOWN\",\n}\n\nfunc GetIPProto(id int) string {\n  return IPProtocols[id]\n}\n"

echo -e "\nvar IPProtocolIDs = map[string] int {"
egrep -v "^#" /etc/protocols | grep -v "for experimentation and testing" | awk '{if( $2 != "" && $1 != "ip"){ print "  \"" $3 "\": " $2 ","}}'
echo -e "  \"UNKNOWN\": 255,\n}\n\nfunc GetIPProtoID(name string) (uint64, bool) {\n  ret, ok := IPProtocolIDs[name]\n  return uint64(ret), ok\n}\n"

exit 0
