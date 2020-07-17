#ifndef CTAPLIB_H_INCLUDED
#define CTAPLIB_H_INCLUDED

  int get_supported_algorithm(size_t pubKeyCredParams_size, struct cbor_item_t **pubKeyCredParams);
  
  __u8 get_options(size_t options_size, struct cbor_pair *options);
  
  int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
  
  int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
  
  unsigned char *readFile(const char *file);
  
  bool verifySignature(unsigned char *hash, int hashLength, ECDSA_SIG *signature, EVP_PKEY *pubKey);
  
  EVP_PKEY *generate_key();
  
  int user_permission();
  
  int extract_coords(__u8 **x_coord, __u8 **y_coord, EC_KEY *newEcKey);
  
  void SHA256_hash(const void *rpId, size_t rpId_length, unsigned char *rpIdHash);
  
  void construct_COSE_public_key(int kty, int alg, int crv, unsigned char *x, unsigned char *y, int coord_size, cbor_item_t **Cose_key);
  
  void construct_public_key_credential_source(cbor_item_t **object, unsigned char *privateKey, int privateKeySize, char *relyingPartyID, __u8 *userHandle, size_t userHandleLength);

  //void* create_shared_data(size_t size);

  void ctaphid_init(__u8 *nonce,__u16 nonce_length, __u8 **buffer);

  int ctap_cbor_make_credential(__u8 payload[], __u16 payload_length, __u8 **buffer);
#endif