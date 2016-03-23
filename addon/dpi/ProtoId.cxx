/////////////////////////////////////////////////////////////////////////////////
//
// ProtoId.cxx
//
// libprotoident API usage wrapper library that takes care of calling the
// approrpiate functions and exposing the API to C (which, in turn, can be used
// by Google Go).
//
// Written by Lennart Elsen lel@open.ch, July 2014
// Copyright (c) 2014 Open Systems AG, Switzerland
// All Rights Reserved.
// 
/////////////////////////////////////////////////////////////////////////////////
#include "ProtoId.h"

#include <stdio.h>

extern "C" {
#include <stdint.h>
#include <stdlib.h>

  CProtoId * ProtoId_new() {
    ProtoId *t = new ProtoId();
    
    return (CProtoId *) t;
  }

  int ProtoId_initLPI(const CProtoId *inst) {
    ProtoId *t = (ProtoId *) inst;

    return t->initLPI();
  }

  void ProtoId_freeLPI(const CProtoId *inst) {
    ProtoId *t = (ProtoId *) inst;

    t->freeLPI();
  }

  
  // this is the main function that should be called from any
  // external code
  uint16_t ProtoId_getLayer7Proto(const CProtoId *inst,
				 uint32_t pl_in,     uint32_t pl_out,
				 uint32_t ob_in,     uint32_t ob_out,
				 uint16_t serv_port, uint16_t cl_port,
				 uint8_t  tr_prot,
				 uint32_t pl_len_in, uint32_t pl_len_out,
				 uint32_t ip_in,     uint32_t ip_out) {
    ProtoId *t = (ProtoId *) inst;
    
    return t->getLayer7Proto(pl_in, pl_out,
			     ob_in, ob_out,
			     serv_port, cl_port,
			     tr_prot,
			     pl_len_in, pl_len_out,
			     ip_in, ip_out);
  }


  int ProtoId_identifyProtocol(const CProtoId *inst) {
    ProtoId *t = (ProtoId *) inst;

    return t->identifyProtocol();
  }

  void ProtoId_setFlowAttributes(const CProtoId *inst,
				 uint32_t pl_in,     uint32_t pl_out,
				 uint32_t ob_in,     uint32_t ob_out,
				 uint16_t serv_port, uint16_t cl_port,
				 uint8_t  tr_prot,
				 uint32_t pl_len_in, uint32_t pl_len_out,
				 uint32_t ip_in,     uint32_t ip_out) {
    ProtoId *t = (ProtoId *) inst;
    
    t->setFlowAttributes(pl_in, pl_out,
			 ob_in, ob_out,
			 serv_port, cl_port,
			 tr_prot,
			 pl_len_in, pl_len_out,
			 ip_in, ip_out);
  }

  uint16_t ProtoId_getProtoByNum(const CProtoId *inst){
    ProtoId *t = (ProtoId *) inst;
    
    return t->getProtoByNum();
  }

  uint16_t ProtoId_getCategoryByNum(const CProtoId *inst){
    ProtoId *t = (ProtoId *) inst;
    
    return t->getCategoryByNum();
  }

  void ProtoId_printId(const CProtoId *inst){
    ProtoId *t = (ProtoId *) inst;

    t->printId();
  }
}

ProtoId::ProtoId() {
  flow_data               = new lpi_data_t();
  l7proto_guess           = new lpi_module_t();
  
  // initialize the guess with unknown, in case someone
  // tries to call the getters without previously calling
  // the identify routine
  l7proto_guess->protocol = LPI_PROTO_UNKNOWN;
  l7proto_guess->category = LPI_CATEGORY_UNKNOWN;
}

ProtoId::~ProtoId(){
  delete flow_data;
  delete l7proto_guess;
}

int ProtoId::initLPI() {
  
  // initialize lpi library
  if( -1 == lpi_init_library() ){
    return -1;
  }

  // initialize flow data struct
  lpi_init_data(flow_data);

  return 0;
}

// clean up the lpi library
void ProtoId::freeLPI() {
  lpi_free_library();
}

// wrapper function performing the individual steps needed
// in order to retrieve a layer 7 protocol guess. The code
// duplication is needed in order to save additional function
// calls. The functionality can be deduced from the methods
// provided in this library
uint16_t ProtoId::getLayer7Proto(uint32_t payloadIn,        uint32_t payloadOut,
				uint32_t observedIn,       uint32_t observedOut,
				uint16_t serverPort,       uint16_t clientPort,
				uint8_t  transportProto,
				uint32_t payloadLenIn,     uint32_t payloadLenOut,
				uint32_t ipIn,             uint32_t ipOut){

  // initialize the flow_data struct
  lpi_init_data(flow_data);

  // explicitly set values in the flow data struct
  flow_data->payload[0]     = payloadIn;
  flow_data->payload[1]     = payloadOut;
  flow_data->observed[0]    = observedIn;
  flow_data->observed[1]    = observedOut;
  flow_data->server_port    = serverPort;
  flow_data->client_port    = clientPort;
  flow_data->trans_proto    = transportProto;
  flow_data->payload_len[0] = payloadLenIn;
  flow_data->payload_len[1] = payloadLenOut;
  flow_data->ips[0]         = ipIn;
  flow_data->ips[1]         = ipOut;

  // perform the guess
  l7proto_guess = lpi_guess_protocol(flow_data);

  // only for debugging purposes
//  printId();

  // return the id of the identified protocol
  return uint16_t(l7proto_guess->protocol);
}

void ProtoId::setFlowAttributes(uint32_t payloadIn,        uint32_t payloadOut,
				uint32_t observedIn,       uint32_t observedOut,
				uint16_t serverPort,       uint16_t clientPort,
				uint8_t  transportProto,
				uint32_t payloadLenIn,     uint32_t payloadLenOut,
				uint32_t ipIn,             uint32_t ipOut){
  flow_data->payload[0]     = payloadIn;
  flow_data->payload[1]     = payloadOut;
  flow_data->observed[0]    = observedIn;
  flow_data->observed[1]    = observedOut;
  flow_data->server_port    = serverPort;
  flow_data->client_port    = clientPort;
  flow_data->trans_proto    = transportProto;
  flow_data->payload_len[0] = payloadLenIn;
  flow_data->payload_len[1] = payloadLenOut;
  flow_data->ips[0]         = ipIn;
  flow_data->ips[1]         = ipOut;
}

uint16_t ProtoId::getCategoryByNum(){
  return uint16_t(l7proto_guess->category);
}

uint16_t ProtoId::getProtoByNum(){
  return uint16_t(l7proto_guess->protocol);
}

int ProtoId::identifyProtocol() {
  l7proto_guess = lpi_guess_protocol(flow_data);

  // return the id of the identified protocol. Return a 
  // negative value in case the identification did not
  // yield any results
  return ( (l7proto_guess->protocol == LPI_PROTO_UNKNOWN) || (l7proto_guess->protocol == LPI_PROTO_UNSUPPORTED) ? -1 : 0 );
}

void ProtoId::printId() {
  printf("L7PROTO:\t%s, CATEGORY:\t%s\n", lpi_print(l7proto_guess->protocol), lpi_print_category(l7proto_guess->category));
}
