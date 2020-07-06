#include "dependencies.h"

int get_supported_algorithm(size_t pubKeyCredParams_size, struct cbor_item_t **pubKeyCredParams){
  int signature_algorithm_to_use = 0;
	int algorithms_wanted[pubKeyCredParams_size];
	cbor_item_t *algorithm = NULL;
	for(int i = 0; i<pubKeyCredParams_size; i++){
		algorithm = cbor_map_handle(pubKeyCredParams[i])[0].value;
    cbor_int_width width = cbor_int_get_width(algorithm);
    int value = 0;
    switch(width){
      case CBOR_INT_8:
        value = cbor_get_uint8(algorithm);
        printf("algorithm is uint8: %d\n", value);
        break;
      case CBOR_INT_16:
        value = cbor_get_uint16(algorithm);
        printf("algorithm is uint16: %d\n", value);
        break;
      case CBOR_INT_32:
        value = cbor_get_uint32(algorithm);
        printf("algorithm is uint32: %d\n", value);
        break;
      default:
        break;
    }
    if(cbor_isa_negint(algorithm)){
      printf("negint\n");
		  algorithms_wanted[i] = -(value+1);
    }
		else{
			algorithms_wanted[i] = value;
		}
	}

	for(int i = 0; i < pubKeyCredParams_size; i++){
		for(int j = 0; j < NUMBER_OF_SIGNATURE_ALGORITHMS; j++){
			if(algorithms_wanted[i] == signature_algorithms[j]){
				signature_algorithm_to_use = signature_algorithms[j];
				break;
			}
			else{
				printf("algorithm %d not supported\n", algorithms_wanted[i]);
			}
		}
		if(signature_algorithm_to_use) break;
	}
  return signature_algorithm_to_use;
}

__u8 get_options(size_t options_size, struct cbor_pair *options){
  __u8 value = 0b00000000;
  #define NUMBER_OF_OPTIONS_KEYS 3
  #define MAX_LENGTH_OF_OPTIONS_KEYS 3
  __u8 known_keys[NUMBER_OF_OPTIONS_KEYS][MAX_LENGTH_OF_OPTIONS_KEYS] = {
      {0x75, 0x70, 0x00}, // UTF-8: "up"    -> 0b00000001
      {0x75, 0x76, 0x00}, // UTF-8: "uv"    -> 0b00000010
      {0x72, 0x6b, 0x00}  // UTF-8: "rk"    -> 0b00000100
    };
  __u8 received_key[3] = {0,0,0};
  __u8 received_key_length = 0;
  __u8 *received_key_handle = 0;
  int same = 1;

  for(int i = 0; i<options_size; i++){
    if(cbor_isa_string(options[i].key)){
      received_key_length = cbor_string_length(options[i].key);
      if(received_key_length > 3){ // keys longer than 3 are invalid
        value += 0x80;
        break; 
      }
      received_key_handle = cbor_string_handle(options[i].key);
      for(int j = 0; j<MAX_LENGTH_OF_OPTIONS_KEYS;j++ ){
        received_key[j] = 0x00; //reset key
      }
      for(int j=0;j<received_key_length;j++){
        received_key[j] = received_key_handle[j];
      }
      for(int k = 0; k<NUMBER_OF_OPTIONS_KEYS; k++){
        for(int l = 0; l<MAX_LENGTH_OF_OPTIONS_KEYS; l++){
          if(known_keys[k][l] == received_key[l]){
            same = 1;
          }
          else{
            same = 0;
          }
          if(!same) break;
        }
        if(same) value += pow(2, k);
      }
    }
  }
  return value;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()));
        //handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv));
        //handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len));
        // handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len));
        // handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()));
        // handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv));
        // handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len));
        // handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len));
        // handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

/* taken from https://stackoverflow.com/questions/22059189/read-a-file-as-byte-array chosen answer */
unsigned char *readFile(const char *file){
	FILE *fileptr;
	unsigned char *buffer;
	long filelen;
	fileptr = fopen(file, "rb");  // Open the file in binary mode
	fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
	filelen = ftell(fileptr);             // Get the current byte offset in the file
	rewind(fileptr);                      // Jump back to the beginning of the file
	buffer = (unsigned char *)malloc(filelen * sizeof(unsigned char)); // Enough memory for the file
	if(!fread(buffer, filelen, 1, fileptr)){
		// handle error
	}; // Read in the entire file
	fclose(fileptr); // Close the file
return buffer;
}

//original code
bool verifySignature(unsigned char *hash, int hashLength, ECDSA_SIG *signature, EVP_PKEY *pubKey){
	EC_KEY *eckey;
	eckey = EVP_PKEY_get1_EC_KEY(pubKey);
	int truth = ECDSA_do_verify(hash, hashLength, signature, eckey);
	printf("truth is: %d", truth);
	return truth;
}

// code taken and dapted from: http://fm4dd.com/openssl/eckeycreate.shtm
EVP_PKEY *generate_key(){
	BIO               *outbio = NULL;
  EC_KEY            *myecc  = NULL;
  EVP_PKEY          *pkey   = NULL;
  //int               *eccgrp;

	OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_PEM_strings();

	outbio  = BIO_new(BIO_s_file());
  outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

  myecc = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

	if (! (EC_KEY_generate_key(myecc)))
    BIO_printf(outbio, "Error generating the ECC key.");

	pkey=EVP_PKEY_new();
  if (!EVP_PKEY_assign_EC_KEY(pkey,myecc))
    BIO_printf(outbio, "Error assigning ECC key to EVP_PKEY structure.");

 if(!PEM_write_bio_PrivateKey(outbio, pkey, NULL, NULL, 0, 0, NULL))
    BIO_printf(outbio, "Error writing private key data in PEM format");

return pkey;
}

int user_permission(){
	int message_pid = fork();
	if(message_pid == 0){
		int answer = system("zenity --question --text='allow registration/?'");
		if(answer == 0){
			exit(0);
		}
		else{
			exit(1);
		}
	}
	int exitstatus;
	waitpid(message_pid, &exitstatus, 0); // wait for user interaction
	int es = WEXITSTATUS(exitstatus);
	return !es;
}

int extract_coords(__u8 **x_coord, __u8 **y_coord, EC_KEY *newEcKey){
	const EC_POINT *public = EC_KEY_get0_public_key(newEcKey);
	EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	EC_POINT_get_affine_coordinates_GFp(ec_group, public, x,y, NULL);
	int big_size = BN_num_bytes(x);
	*x_coord = (__u8 *) malloc(big_size * sizeof(__u8));
	BN_bn2bin(x, *x_coord);
	*y_coord = (__u8 *) malloc(big_size * sizeof(__u8));
	BN_bn2bin(y, *y_coord);
	return big_size;
}

void SHA256_hash(const void *rpId, size_t rpId_length, unsigned char *rpIdHash){
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	unsigned int md_len;
	md = EVP_get_digestbyname("sha256");
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, rpId, rpId_length);
	EVP_DigestFinal_ex(mdctx, rpIdHash, &md_len);
	EVP_MD_CTX_free(mdctx);
}

void construct_COSE_public_key(int kty, int alg, int crv, unsigned char *x, unsigned char *y, int coord_size, cbor_item_t **Cose_key){
	//cbor_item_t *COSE_public_key = cbor_new_definite_map(5); // labels: -1(crv): 1; -2(x); -3(y); 1(kty): 2; 3(alg): -7;
	*Cose_key = cbor_new_definite_map(5);
	struct cbor_pair pair;
	// add key type to map
	pair.key = cbor_build_uint8(1);
	pair.value = cbor_build_uint8(kty);
	cbor_map_add(*Cose_key, pair);
	// add alg map
	pair.key = cbor_build_uint8(3);
	if(alg < 0){
		alg += 1;
		cbor_mark_negint(pair.value);
	}
	pair.value = cbor_build_uint8(alg);
	cbor_map_add(*Cose_key, pair);
	// add curve to map
	pair.key = cbor_build_uint8(0);
	cbor_mark_negint(pair.key);
	if(crv < 0){
		crv += 1;
		cbor_mark_negint(pair.value);
	}
	pair.value = cbor_build_uint8(crv);
	cbor_map_add(*Cose_key, pair);
	// add x coordinate to map
	pair.key = cbor_build_uint8(1);
	cbor_mark_negint(pair.key);
	pair.value = cbor_build_bytestring(x, coord_size);
	cbor_map_add(*Cose_key, pair);
	// add y coordinate to map
	pair.key = cbor_build_uint8(2);
	cbor_mark_negint(pair.key);
	pair.value = cbor_build_bytestring(y, coord_size);
	cbor_map_add(*Cose_key, pair);
	return;
}

void construct_public_key_credential_source(cbor_item_t **object, unsigned char *privateKey, int privateKeySize, char *relyingPartyID, __u8 *userHandle, size_t userHandleLength){
	*object = cbor_new_definite_map(4);
	struct cbor_pair pair;
	// add type to map
	pair.key = cbor_build_string("type");
	pair.value = cbor_build_string("public-key");
	cbor_map_add(*object, pair);
	// add x coordinate to map
	pair.key = cbor_build_string("private-key");
	pair.value = cbor_build_bytestring(privateKey, privateKeySize);
	cbor_map_add(*object, pair);
	// add rpId to map
	pair.key = cbor_build_string("rpId");
	pair.value = cbor_build_string(relyingPartyID);
	cbor_map_add(*object, pair);
	// add userHandle to map
	pair.key = cbor_build_string("userHandle");
	pair.value = cbor_build_bytestring(userHandle, userHandleLength);
	cbor_map_add(*object, pair);
	return;
}