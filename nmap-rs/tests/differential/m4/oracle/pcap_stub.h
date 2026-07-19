#ifndef PCAP_STUB_H
#define PCAP_STUB_H
#include <sys/time.h>
typedef struct pcap pcap_t;
struct pcap_pkthdr { struct timeval ts; unsigned int caplen; unsigned int len; };
struct bpf_program { unsigned int bf_len; struct bpf_insn *bf_insns; };
typedef int bpf_int32; typedef unsigned int bpf_u_int32;
#define PCAP_ERRBUF_SIZE 256
#endif
