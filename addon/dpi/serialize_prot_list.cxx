///////////////////////////////////////////////////////////////////////////////// 
// 
// serialize_prot_list.cxx 
// 
// Helper binary to extract the protocol-category mappings directly from
// libprotoident such that they are made available to goquery
// 
// Written by Lennart Elsen
//        and Fabian  Kohn, July 2014 
// Copyright (c) 2014 Open Systems AG, Switzerland 
// All Rights Reserved.
//
/////////////////////////////////////////////////////////////////////////////////
/* This code has been developed by Open Systems AG
 *
 * goProbe is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * goProbe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with goProbe; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "libprotoident.h"

int main(){
  lpi_init_library();
  lpi_serialize_protocol_list();
  lpi_free_library();
  return 0;
}
