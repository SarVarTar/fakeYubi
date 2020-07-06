#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <linux/types.h>
#include <linux/hid.h>
#include <linux/usb/ch9.h>
#include "sendpackages.h"

void send_packages(__u8 *package, int data_to_write[], __u8 *payload, __u8 cid[4], __u8 ctap_cmd, __u16 payload_Length){
	int payload_Index = 0;
	int sequence = 0x00;
	int done = 0;
	int firstPackage = 1;
	
	while(data_to_write[0] == 1){	// wait if packages are still sending
		printf("packages still pending...\n");
		sleep(0.1);
	}
	
	if(data_to_write[0] == 2) data_to_write[0] = 0;

	while(!done){
		printf("start composing package\n");
		if(firstPackage){
			printf("resetting package\n");
			for(int i = 0; i< 64; i++){	// reset package
				package[i] = 0;
			}
			for(int i=0; i < 4; i++){	// set CID
				package[i] = cid[i];
			}
			package[4] = ctap_cmd;	// set command byte
			package[5] = ((payload_Length) & 0xFF00) >> 8; 	// upper part of data length (payload + 1 byte status code) 
			printf("upper part of packagelength: %d\n", package[5]);
			package[6] = ((payload_Length) & 0xFF) >> 0; 	// lower part of data length (payload + 1 byte status code)
			printf("lower part of packagelength: %d\n", package[6]);
			printf("filling payload\n");
			for(int i = 7; i < 64; i++){	// fill rest with payload
				package[i] = payload[payload_Index];
				payload_Index++;
				if(payload_Index >= payload_Length){
					printf("payload index: %d >= payload length: %d\n", payload_Index, payload_Length);
					break;
				} 
			}
			printf("payload index is at %d\n", payload_Index);
			data_to_write[0] = 1;	// let IN endpoint send the package
			firstPackage = 0;	// first package send
		}
		else{
			printf("resetting package\n");
			for(int i = 0; i< 64; i++){	// reset package
				package[i] = 0;
			}
			if(payload_Index >= payload_Length){	// stop if all data is send
				printf("no more data to send\n");
				done = 1;
				continue;
			} 
			else{	// subsequent packages
				printf("composing package sequence: %d\n", sequence);
				for(int i=0; i < 4; i++){	// set CID
					package[i] = cid[i];
				}
				package[4] = sequence; // sequence number of package
				sequence++;
				printf("filling payload\n");
				for(int i = 5; i < 64; i++){	// fill rest with payload
					package[i] = payload[payload_Index];
					payload_Index++;
					if(payload_Index > payload_Length-1) break;
				}
				printf("payload index is at: %d\n", payload_Index);
				data_to_write[0] = 1;	// send package
			}
		}
		while(data_to_write[0]){	// wait till package is send
						sleep(0.01);	// a short delay is necessary,
													// or else the code breaks ¯\_(ツ)_/¯
		}
	}
	return;
}

void send_keepalive_waiting_for_up(__u8 *package, int data_to_write[],__u8 cid[4]){
	while(data_to_write[0] == 1){	// wait if packages are still sending
		printf("packages still pending...\n");
		sleep(0.1);
	}
	if(data_to_write[0] == 2) data_to_write[0] = 0;
	for(int i=0; i < 4; i++){
		package[i] = cid[i];
	}
	package[4] = 0xbb;
	package[5] = 0x00;
	package[6] = 0x01;
	package[7] = 0x02;
	for(int i = 8; i < 64; i++){
		package[i] = 0x00;
	}
	data_to_write[0] = 2;
	return;
}

void send_keepalive_processing(__u8 *package, int data_to_write[], __u8 cid[4]){
	while(data_to_write[0] == 1){	// wait if packages are still sending
		printf("packages still pending...\n");
		sleep(0.1);
	}
	if(data_to_write[0] == 2) data_to_write[0] = 0;
	for(int i=0; i < 4; i++){
		package[i] = cid[i];
	}
	package[4] = 0xbb;
	package[5] = 0x00;
	package[6] = 0x01;
	package[7] = 0x01;
	for(int i = 8; i < 64; i++){
		package[i] = 0x00;
	}
	data_to_write[0] = 2;
	return;
}