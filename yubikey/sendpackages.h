#ifndef SENDPACKAGES_H_INCLUDED
#define SENDPACKAGES_H_INCLUDED

  void send_packages(__u8 *package, int write_flag[], __u8 *payload, __u8 cid[4], __u8 ctap_cmd, __u16 payload_Length);
  void send_keepalive_waiting_for_up(__u8 *package, int data_to_write[], __u8 cid[4]);
  void send_keepalive_processing(__u8 *package, int data_to_write[], __u8 cid[4]);
#endif