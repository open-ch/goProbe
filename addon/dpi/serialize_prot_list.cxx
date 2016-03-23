///////////////////////////////////////////////////////////////////////////////// 
// 
// serialize_prot_list.cxx 
// 
// Helper binary to extract the protocol-category mappings directly from
// libprotoident such that they are made available to goquery
// 
// Written by Lennart Elsen lel@open.ch, July 2014 
// Copyright (c) 2014 Open Systems AG, Switzerland 
// All Rights Reserved.
//
/////////////////////////////////////////////////////////////////////////////////
#include "libprotoident.h"

int main(){
  lpi_init_library();
  lpi_serialize_protocol_list();
  lpi_free_library();
  return 0;
}
