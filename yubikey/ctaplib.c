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

/**/// Source: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
/**/int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
/**/            unsigned char *iv, unsigned char *ciphertext)
/**/{
/**/    EVP_CIPHER_CTX *ctx;
/**/    int len;
/**/    int ciphertext_len;
/**/
/**/    /* Create and initialise the context */
/**/    if(!(ctx = EVP_CIPHER_CTX_new()));
/**/        //handleErrors();
/**/    //
/**/    //Initialise the encryption operation. IMPORTANT - ensure you use a key
/**/    //and IV size appropriate for your cipher
/**/    //In this example we are using 256 bit AES (i.e. a 256 bit key). The
/**/    //IV size for *most* modes is the same as the block size. For AES this
/**/    //is 128 bits
/**/    //
/**/    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv));
/**/        //handleErrors();
/**/    //
/**/    //Provide the message to be encrypted, and obtain the encrypted output.
/**/    //EVP_EncryptUpdate can be called multiple times if necessary
/**/    //
/**/    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len));
/**/        // handleErrors();
/**/    ciphertext_len = len;
/**/    //
/**/    //Finalise the encryption. Further ciphertext bytes may be written at
/**/    //this stage.
/**/    //
/**/    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len));
/**/        // handleErrors();
/**/    ciphertext_len += len;
/**/    /* Clean up */
/**/    EVP_CIPHER_CTX_free(ctx);
/**/    return ciphertext_len;
/**/}
/**/
/**/int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
/**/            unsigned char *iv, unsigned char *plaintext)
/**/{
/**/    EVP_CIPHER_CTX *ctx;
/**/    int len;
/**/    int plaintext_len;
/**/
/**/    /* Create and initialise the context */
/**/    if(!(ctx = EVP_CIPHER_CTX_new()));
/**/        // handleErrors();
/**/    //
/**/    //Initialise the decryption operation. IMPORTANT - ensure you use a key
/**/    //and IV size appropriate for your cipher
/**/    //In this example we are using 256 bit AES (i.e. a 256 bit key). The
/**/    //IV size for *most* modes is the same as the block size. For AES this
/**/    //is 128 bits
/**/    //
/**/    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv));
/**/        // handleErrors();
/**/    //
/**/    //Provide the message to be decrypted, and obtain the plaintext output.
/**/    //EVP_DecryptUpdate can be called multiple times if necessary.
/**/    //
/**/    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len));
/**/        // handleErrors();
/**/    plaintext_len = len;
/**/    //
/**/    //Finalise the decryption. Further plaintext bytes may be written at
/**/    //this stage.
/**/    //
/**/    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len));
/**/        // handleErrors();
/**/    plaintext_len += len;
/**/    /* Clean up */
/**/    EVP_CIPHER_CTX_free(ctx);
/**/    return plaintext_len;
/**/}

/**/// taken from https://stackoverflow.com/questions/22059189/read-a-file-as-byte-array chosen answer
/**/unsigned char *readFile(const char *file){
/**/	FILE *fileptr;
/**/	unsigned char *buffer;
/**/	long filelen;
/**/	fileptr = fopen(file, "rb");  // Open the file in binary mode
/**/	fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
/**/	filelen = ftell(fileptr);             // Get the current byte offset in the file
/**/	rewind(fileptr);                      // Jump back to the beginning of the file
/**/	buffer = (unsigned char *)malloc(filelen * sizeof(unsigned char)); // Enough memory for the file
/**/	if(!fread(buffer, filelen, 1, fileptr)){
/**/		// handle error
/**/	}; // Read in the entire file
/**/	fclose(fileptr); // Close the file
/**/return buffer;
/**/}


bool verifySignature(unsigned char *hash, int hashLength, ECDSA_SIG *signature, EVP_PKEY *pubKey){
	EC_KEY *eckey;
	eckey = EVP_PKEY_get1_EC_KEY(pubKey);
	int truth = ECDSA_do_verify(hash, hashLength, signature, eckey);
	printf("truth is: %d", truth);
	return truth;
}

/**/// code adapted from: http://fm4dd.com/openssl/eckeycreate.shtm
/**/EVP_PKEY *generate_key(){
/**/	BIO               *outbio = NULL;
/**/  EC_KEY            *myecc  = NULL;
/**/  EVP_PKEY          *pkey   = NULL;
/**/
/**/	OpenSSL_add_all_algorithms();
/**/  ERR_load_BIO_strings();
/**/  ERR_load_PEM_strings();
/**/
/**/	outbio  = BIO_new(BIO_s_file());
/**/  outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
/**/
/**/  myecc = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
/**/
/**/	if (! (EC_KEY_generate_key(myecc)))
/**/    BIO_printf(outbio, "Error generating the ECC key.");
/**/
/**/	pkey=EVP_PKEY_new();
/**/  if (!EVP_PKEY_assign_EC_KEY(pkey,myecc))
/**/    BIO_printf(outbio, "Error assigning ECC key to EVP_PKEY structure.");
/**/
/**/ if(!PEM_write_bio_PrivateKey(outbio, pkey, NULL, NULL, 0, 0, NULL))
/**/    BIO_printf(outbio, "Error writing private key data in PEM format");
/**/
/**/return pkey;
/**/}


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

/*  should create a shared memory for use with asynchronous commands,
    but initializattion of it does not work for unknown reasons */
// void* create_shared_data(size_t size){
//   int protection = PROT_READ | PROT_WRITE;
//   int visibility = MAP_SHARED | MAP_ANONYMOUS;
//   void* ret = mmap(NULL, size, protection, visibility, -1,0);
//   return ret;
// }

// sends new channel id + basic information
void ctaphid_init(__u8 *nonce,__u16 nonce_length, __u8 **buffer){
	time_t t;
  *buffer = malloc(17 * sizeof(__u8));
	srand((unsigned) time(&t));								
	for(int i = 0; i < nonce_length; i++){ 	// Keep 8 Byte Nonce (payload)
		(*buffer)[i] = nonce[i];
		}
	(*buffer)[nonce_length] = rand() % 255; 	// new Channel ID 2nd byte
	(*buffer)[nonce_length+1] = rand() % 255; 	// new Channel ID 1st byte
	(*buffer)[nonce_length+2] = rand() % 255; 	// new Channel ID 3rd byte
	(*buffer)[nonce_length+3] = rand() % 255; 	// new Channel ID 4th byte
	(*buffer)[nonce_length+4] = 0x02; 	// CTAPHID Protocol Version
	(*buffer)[nonce_length+5] = 0x05; 	// Major Device Number
	(*buffer)[nonce_length+6] = 0x02; 	// Minor Device Number
	(*buffer)[nonce_length+7] = 0x01; 	// Build Device Version Number
	(*buffer)[nonce_length+8] = 0x08+0x04; 	// Capabilites Flags:
																				// 0x08: NO CTAPHID_MSG
																				// 0x04: CTAPHID_CBOR
																				// 0x01: CTAPHID_WINK
	printf("sending init package:\n");
	for(int i = 0; i <17; i++){
		printf("%02x ", (*buffer)[i]);
	}
	printf("\n");
  return;
}

//generates a new credential based on CredentialCreationOptions
int ctap_cbor_make_credential(__u8 payload[], __u16 payload_length, __u8 **buffer){
/**/
/**/	// init possible input data
/**/	cbor_mutable_data clientDataHash = NULL;
/**/	struct cbor_pair * relying_party= NULL;
/**/	struct cbor_pair * user= NULL;
/**/	struct cbor_item_t ** pubKeyCredParams= NULL;
/**/	size_t pubKeyCredParams_size= 0;
/**/	struct cbor_pair * options_map= NULL;
/**/	size_t options_map_size= 0;
/**/
/**/	// load input data
// /**/	__u8 source[(payload_length-1)];	//cut cbor command byte from payload
// /**/	for(int i = 1; i<payload_length; i++){
// /**/		source[i-1] = payload[i];
// /**/	}
/**/
/**/	struct cbor_load_result result;
/**/	cbor_item_t* json_map = cbor_load(payload, payload_length, &result); // loading cbor data
/**/	struct cbor_pair * fields = cbor_map_handle(json_map); // decode cbor map into key/value pairs
/**/	size_t number_of_keys = cbor_map_size(json_map);	// extract number of keys
/**/
/**/	// load key values of input
/**/	int keys[number_of_keys];
/**/	for(int i = 0; i < number_of_keys; i++){
/**/		keys[i] = cbor_get_uint8(fields[i].key);
/**/	}
/**/	
/**/	// extract input parameters
/**/	for(int i = 0; i< number_of_keys; i++){
/**/		switch(keys[i]){
/**/			case 1: // clientDataHash
/**/				clientDataHash = cbor_bytestring_handle(fields[0].value); // extract clientDataHash
/**/				break;
/**/			case 2: // rp
/**/				relying_party = cbor_map_handle(fields[1].value);	// extract relying party struct
/**/				break;
/**/			case 3:	// user
/**/				user = cbor_map_handle(fields[2].value);	//extract user struct
/**/				break;
/**/			case 4: // pubKeyCredParams
/**/				pubKeyCredParams = cbor_array_handle(fields[3].value); // extract pubKeyCredParams Array
/**/				pubKeyCredParams_size = cbor_array_size(fields[3].value);	// extract size of pubKeyCredParams
/**/				break;
/**/			case 5: // excludeList
/**/				// not implemented yet
/**/				break;
/**/			case 6: // extensions
/**/				// not implemented yet
/**/				break;
/**/			case 7: // options
/**/				options_map = cbor_map_handle(fields[6].value);
/**/				options_map_size = cbor_map_size(fields[6].value);
/**/				break;
/**/			case 8: // pinUvAuthParam
/**/				// not implemented yet
/**/				break;
/**/			case 9: // pinUvAuthProtocol
/**/				// not implemented yet
/**/				break;
/**/			default: // unknown parameter
/**/				break;
/**/		}
/**/	}
/**/
/**/	// check wanted algorithms
/**/	int COSE_algorithm = get_supported_algorithm(pubKeyCredParams_size, pubKeyCredParams);
/**/	if(COSE_algorithm == 0){
/**/		printf("CTAP2_ERR_UNSUPPORTED_ALGORITHM\n");
/**/		//status[0] = 0x26;
/**/    (*buffer)[0] = 0x26;
/**/		//send_packages(package, write_flag, status, cid, 0x90, 0x01);
/**/		return 1;
/**/	}
/**/
/**/	// check options and set flags: 0x01 -> up; 0x02 -> uv; 0x04 -> rk; 0x80 -> unknown option; 0x08..0x40 usable for extension
/**/	__u8 options = get_options(options_map_size, options_map);
/**/	if(options >= 0x80){
/**/		printf("CTAP2_ERR_INVALID_OPTION");
/**/    (*buffer[0]) = 0x2C;
/**/		return 1;
/**/	}
/**/	if(options > 0x01){	// only "up" (user presence) supported yet
/**/		printf("CTAP2_ERR_UNSUPPORTED_OPTION");
/**/    (*buffer[0]) = 0x2B;
/**/		return 1;
/**/	}
/**/
/**/	// check extensions (not implemented)
/**/
/**/	// process exclude list (not implemented)
/**/
/**/	// get user verification (not implemented)
/**/
/**/	// perform credProtection (not implemented)
/**/
// /**/	// start sending keep alives
// /**/	send_keepalive_waiting_for_up(package, write_flag, cid);
/**/	// wait for user permission
/**/	if(!user_permission()){ 
/**/		printf("CTAP2_ERR_OPERATION_DENIED");
/**/		//status[0] = 0x27;
/**/    (*buffer[0]) = 0x27;
/**/		//send_packages(package, write_flag, status, cid, 0x90, 0x01);
/**/		return 1;
/**/	}
// /**/	// send processing package
// /**/	send_keepalive_processing(package, write_flag, cid);
// /**/	sleep(0.1);
/**/
/**/	// generate credential key pair
/**/	EVP_PKEY *newkey = generate_key();
/**/	EC_KEY *newEcKey = EVP_PKEY_get1_EC_KEY(newkey);
/**/	unsigned char *newkey_buf;
/**/	int newkey_bufsize = i2d_ECPrivateKey(newEcKey, NULL);
/**/	newkey_buf = (unsigned char*) malloc(newkey_bufsize * sizeof(unsigned char));
/**/	i2d_ECPrivateKey(newEcKey, &newkey_buf);
/**/
/**/	// extract x and y coordinate of public key
/**/	__u8 *x_coord;
/**/	__u8 *y_coord;
/**/	int coord_size = extract_coords(&x_coord, &y_coord, newEcKey);
/**/
/**/	// store key if residential key (rk) options parameter is present (not implemented)
/**/
/**/	// hash relying party id
/**/	unsigned char rpIdHash[32];	
/**/	unsigned char *rpId;
/**/	int rpId_length;
/**/	rpId = cbor_string_handle(relying_party[0].value);
/**/	rpId_length = cbor_string_length(relying_party[0].value);
/**/	SHA256_hash(rpId, rpId_length, rpIdHash);
/**/
/**/	// set flags
/**/	__u8 flags = 0b01000001;
/**/	// set signCount
/**/	__u32 signCount;
/**/	FILE *fp = fopen("./counter.txt", "r+");
/**/	if(!fscanf(fp, "%d", &signCount)){
/**/		//handle error
/**/	};
/**/
/**/	// set public key according to COSE encoding
/**/	cbor_item_t *COSE_public_key;
/**/	construct_COSE_public_key(2, -7, 1, x_coord, y_coord, coord_size, &COSE_public_key); 
/**/	// serialize public key
/**/	__u8 serialized_public_key_buffer[1024];
/**/	int public_key_size = cbor_serialize(COSE_public_key, serialized_public_key_buffer, 1024);
/**/	__u8 serialized_public_key[public_key_size];
/**/	for(int i = 0; i<public_key_size; i++){
/**/		serialized_public_key[i] = serialized_public_key_buffer[i];
/**/	}
/**/
/**/	// create public key credential source as CBOR map
/**/	cbor_item_t *publicKeyCredentialSource;
/**/	char *relying_party_id = cbor_string_handle(relying_party[0].value); 
/**/	__u8 *user_handle = cbor_bytestring_handle(user[0].value);
/**/	int user_handle_length = cbor_bytestring_length(user[0].value);
/**/	construct_public_key_credential_source(&publicKeyCredentialSource, newkey_buf, newkey_bufsize, relying_party_id, user_handle, user_handle_length);
/**/	// serialize public key credential source
/**/	__u8 serialization_buffer[1024];
/**/	int size = cbor_serialize(publicKeyCredentialSource, serialization_buffer, 1024);
/**/	__u8 serialized_publicKeyCredentialSource[size];
/**/	for(int i = 0; i < size; i++){
/**/		serialized_publicKeyCredentialSource[i] = serialization_buffer[i];
/**/	} 
/**/
/**/	// encrypt credential source => credential ID
/**/  unsigned char ciphertext[1024];
/**/	__u16 credentialIdLength = encrypt (serialized_publicKeyCredentialSource, size, sym_key, iv,
/**/                            ciphertext);
/**/	__u8 credentialID[credentialIdLength];
/**/	for(int i = 0; i < credentialIdLength; i++){
/**/		credentialID[i] = ciphertext[i];
/**/	} 
/**/
/**/  // construct attested credential data
/**/	int attCredDataLen = 16 + 2 + credentialIdLength + public_key_size;
/**/	__u8 attestedCredentialData[attCredDataLen];
/**/	for(int i = 0; i< 16; i++){ // 16 bytes aaguid ID
/**/		attestedCredentialData[i] = aaguid[i];
/**/	}
/**/	attestedCredentialData[16] = (credentialIdLength >> 8) & 0xFF;// upper part of credential ID length
/**/	attestedCredentialData[17] = credentialIdLength & 0xFF; // lower part of credential ID length
/**/	for(int i = 0; i < credentialIdLength; i++){ // credentialIdLength bytes credentialID
/**/		attestedCredentialData[i+18] = credentialID[i];
/**/	}
/**/	for(int i = 0; i < public_key_size; i++){ // the public key bytes
/**/		attestedCredentialData[i+credentialIdLength+18] = serialized_public_key[i];
/**/	}
/**/
/**/	// construct authenticator Data
/**/	int sizeof_authenticatorData = sizeof(attestedCredentialData)+37;
/**/	__u8 authenticatorData[sizeof_authenticatorData];
/**/	for(int i = 0; i<32; i++){
/**/		authenticatorData[i] = rpIdHash[i];
/**/	} 
/**/	authenticatorData[32] = flags;
/**/	authenticatorData[33] = (signCount >> 24) & 0xFF;
/**/	authenticatorData[34] = (signCount >> 16) & 0xFF;
/**/	authenticatorData[35] = (signCount >> 8) & 0xFF;
/**/	authenticatorData[36] = signCount & 0xFF;
/**/	for(int i = 0; i < attCredDataLen; i++){
/**/		authenticatorData[i+37] = attestedCredentialData[i];
/**/	}
/**/
/**/	// create attestation signature
/**/	OpenSSL_add_all_algorithms();
/**/	int message_size = sizeof(authenticatorData) + sizeof(clientDataHash);
/**/	char message[message_size]; 
/**/	unsigned char sigHash[32];	
/**/	EVP_MD_CTX *mdctx_sign;
/**/	const EVP_MD *md_sign;
/**/	unsigned int md_len_sign;
/**/	md_sign = EVP_get_digestbyname("sha256");
/**/	mdctx_sign = EVP_MD_CTX_new();
/**/	EVP_DigestInit_ex(mdctx_sign, md_sign, NULL);
/**/	EVP_DigestUpdate(mdctx_sign, message, message_size);
/**/	EVP_DigestFinal_ex(mdctx_sign, sigHash, &md_len_sign);
/**/	EVP_MD_CTX_free(mdctx_sign);
/**/	ECDSA_SIG *signature;
/**/	signature = ECDSA_do_sign(sigHash, 32, newEcKey);
/**/	
/**/	// construct attestation object
/**/	cbor_item_t *attestation_object = cbor_new_definite_map(3); // CBOR Map mit 3 feldern:
/**/																															//  fmt -> string; authData -> bytearray; attStmt -> cbor map;
/**/	struct cbor_pair pair;
/**/	// add format
/**/	pair.key = cbor_build_uint8(1);
/**/	pair.value = cbor_build_string("packed");
/**/	cbor_map_add(attestation_object, pair);
/**/	// add authData
/**/	pair.key = cbor_build_uint8(2);
/**/	pair.value = cbor_build_bytestring(authenticatorData, sizeof_authenticatorData);
/**/	cbor_map_add(attestation_object, pair);
/**/	// add attStmt
/**/	unsigned char bb[0];
/**/	unsigned char *bbb = bb;
/**/	i2d_ECDSA_SIG(signature, &bbb);
/**/	cbor_item_t *attStmt = cbor_new_definite_map(2);
/**/	pair.key = cbor_build_string("alg");
/**/	pair.value = cbor_build_uint8(6);
/**/	cbor_mark_negint(pair.value);
/**/	cbor_map_add(attStmt, pair);
/**/	pair.key = cbor_build_string("sig");
/**/	pair.value = cbor_build_bytestring(bbb, ECDSA_size(newEcKey));
/**/	cbor_map_add(attStmt, pair);
/**/	pair.key = cbor_build_uint8(3);
/**/	pair.value = attStmt;
/**/	cbor_map_add(attestation_object, pair);
/**/
/**/	// serialize attestation object
/**/	__u8 buff[1024];
/**/	__u16 l = cbor_serialize(attestation_object, buff, 1024);
/**/	printf("serialized length: %d", l);
/**/  *buffer = malloc((l+1) * sizeof(__u8));
/**/  (*buffer)[0] = 0x00;
/**/  for(int i = 0; i < l; i++){
/**/    (*buffer)[i+1] = buff[i];
/**/  }
/**/  return l+1;
/**/
/**/	//////// kept for possible future authentication
/**/	// 	//// extract private key from decrypted user handle
/**/  //   // decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
/**/  //   //                             decryptedtext);
/**/	// 	// 
/**/	// 	// cbor_item_t *deserialized = cbor_load(decryptedtext, decryptedtext_len, &result);
/**/	// 	// struct cbor_pair *maap = cbor_map_handle(deserialized);
/**/	// 	// int size = cbor_bytestring_length(maap[1].value);
/**/	// 	// cbor_mutable_data bytes = cbor_bytestring_handle(maap[1].value);
/**/	// 	// printf("bytes: %s", bytes);
/**/	// 	// 
/**/	// 	///////////////////////////////////////////////////////
/**/ }
