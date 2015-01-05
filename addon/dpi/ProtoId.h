///////////////////////////////////////////////////////////////////////////////// 
// 
// ProtoId.h
// 
// libprotoident API usage wrapper library that takes care of calling the 
// approrpiate functions and exposing the API to C (which, in turn, can be used 
// by Google Go).
// 
// Written by Lennart Elsen and Fabian Kohn, July 2014 
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
#ifndef ProtoId_h
#define ProtoId_h

#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

  typedef void CProtoId;
  CProtoId *           ProtoId_new();
  int                  ProtoId_initLPI(const CProtoId *inst);
  void                 ProtoId_freeLPI(const CProtoId *inst);

  uint16_t             ProtoId_getLayer7Proto(const CProtoId *inst,
					 uint32_t pl_in,     uint32_t pl_out,
					 uint32_t ob_in,     uint32_t ob_out,
					 uint16_t serv_port, uint16_t cl_port,
					 uint8_t tr_prot,
					 uint32_t pl_len_in, uint32_t pl_len_out,
					 uint32_t ip_in,     uint32_t ip_out);

  int                  ProtoId_identifyProtocol(const CProtoId *inst);
  void                 ProtoId_setFlowAttributes(const CProtoId *inst,
					 uint32_t pl_in,     uint32_t pl_out,
					 uint32_t ob_in,     uint32_t ob_out,
					 uint16_t serv_port, uint16_t cl_port,
					 uint8_t tr_prot,
					 uint32_t pl_len_in, uint32_t pl_len_out,
					 uint32_t ip_in,     uint32_t ip_out);
  uint16_t              ProtoId_getProtoByNum(const CProtoId *inst);
  void                  ProtoId_printId(const CProtoId *inst);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

#include "libprotoident.h"

class ProtoId {
 public:
  // functions used in the dpi package of goProbe
  ProtoId();
  virtual ~ProtoId();

  virtual int           initLPI();
  virtual void          freeLPI();

  virtual uint16_t      getLayer7Proto(uint32_t payloadIn,      uint32_t payloadOut,
				       uint32_t observedIn,     uint32_t observedOut,
				       uint16_t serverPort,     uint16_t clientPort,
				       uint8_t  transportProto,
				       uint32_t payloadLenIn,   uint32_t payloadLenOut,
          		     	       uint32_t ipIn,           uint32_t ipOut);

  // additional interface functions
  virtual void          setFlowAttributes(uint32_t payloadIn,      uint32_t payloadOut,
					  uint32_t observedIn,     uint32_t observedOut,
					  uint16_t serverPort,     uint16_t clientPort,
					  uint8_t  transportProto,
					  uint32_t payloadLenIn,   uint32_t payloadLenOut,
					  uint32_t ipIn,           uint32_t ipOut);

  virtual uint16_t      getCategoryByNum();
  virtual uint16_t      getProtoByNum();

  virtual int           identifyProtocol();

  virtual void          printId();

 private:
  lpi_data_t*           flow_data;
  lpi_module_t*         l7proto_guess;
};

#endif

#endif
