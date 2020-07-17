#include "dependencies.h"

void fakeYubi_interface(__u8 *package, int write_flag[], __u8 *payload,__u16 payload_length, __u8 cid[4], __u8 ctap_cmd){
  __u8 *buffer;
  switch(ctap_cmd){
    case 0x80+0x06:
      printf("CTAPHID_INIT\n");
      ctaphid_init(payload, payload_length, &buffer);
      send_packages(package, write_flag, buffer, cid, ctap_cmd, (__u16)17);
      free(buffer);
      break;
    case 0x80+0x03:
      printf("CTAPHID_MSG\n");
      printf("U2F IS NOT YET SUPPORTED!\n");
      break;
    case 0x80+0x10:
      printf("CTAPHID_CBOR\n");
      __u8* payload_data = payload + 1;//cut cbor_cmd from payload
      switch(payload[0]){
        case 0x01:
          printf("Authenticator make credential\n");
          int size = ctap_cbor_make_credential(payload_data, (payload_length-1), &buffer);
          send_packages(package, write_flag, buffer, cid, 0x90, size);
          free(buffer);
          break;
        case 0x02:
          printf("Authenticator Get Assertion\n");
          break;
        case 0x04:
          printf("Authenticator Get Info\n");
          // authenticatorinfo is static, so no extra function needed
          send_packages(package, write_flag, authenticatorInfoCBOR, cid, 0x90, sizeof(authenticatorInfoCBOR));
          break;
        case 0x06:
          printf("Authenticator Client PIN\n");
          break;
        case 0x07:
          printf("Authenticator Reset\n");
          break;
        case 0x08:
          printf("Authenticator Get Next Assertion\n");
          break;
        case 0x09:
          printf("Authenticator Bio Enrollment\n");
          break;
        case 0x0A:
          printf("Authenticator Credential Management\n");
          break;
        case 0x0B:
          printf("Authenticator Selection\n");
          break;
        case 0x0C:
          printf("Authenticator Config\n");
          break;
        default:
          printf("Something is wrong Jim...\n");
          break;
      }
      break;
    default:
      printf("Something is wrong Jim...\n");
      break;
  }
  return;
}

//  cbor_item_t *unwrap_credential_id(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *decryptedtext) {
// 	  /* Decrypt the ciphertext */
// 		struct cbor_load_result result;
// 		int decryptedtext_len;
//     decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
//                                 decryptedtext);

// 		cbor_item_t *deserialized = cbor_load(decryptedtext, decryptedtext_len, &result);
// 		return deserialized;
//  }