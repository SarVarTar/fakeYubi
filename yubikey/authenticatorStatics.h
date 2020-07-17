#ifndef AUTHENTICATORSTATICS_H_INCLUDED
#define AUTHENTICATORSTATICS_H_INCLUDED
#define NUMBER_OF_SIGNATURE_ALGORITHMS 1
#define NUMBER_OF_STATUS_CODES 

  extern const int signature_algorithms[NUMBER_OF_SIGNATURE_ALGORITHMS];
  extern const __u8 status_codes[NUMBER_OF_STATUS_CODES];
  extern __u8 authenticatorInfoCBOR[129];
  extern __u8 aaguid[16];
  extern __u8 sym_key[32];
  extern __u8 iv[16];
  
#endif