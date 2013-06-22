/* daemonlg.c : Defines the entry point for the application.
*
* Copyright (c) 2013 Aczire Solutions
*        
* All rights reserved.
* 
* Redistribution and use in source and binary forms, with or without 
* modification, are permitted provided that the following conditions 
* are met:
* 
* 1. Redistributions of source code must retain the above copyright 
* notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright 
* notice, this list of conditions and the following disclaimer in the 
* documentation and/or other materials provided with the distribution. 
* 3. Neither the name of Aczire Solutions nor the names of its 
* contributors may be used to endorse or promote products derived from 
* this software without specific prior written permission. 
* 
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
* OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
* 
*/

/*
* This simple program to setup a uni-directional, user-level bridge to 
* create a soft-tap, like daemonlogger.
* It opens two adapters specified by the user and starts a packet 
* copying thread. It receives packets from adapter 1 and sends them down
* to adapter 2.
*/

#include <signal.h>
#include <io.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <share.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <tchar.h>
#include <pcap.h>
#include <winsock.h>

/* Storage data structure used to pass parameters to the threads */
typedef struct _in_out_adapters
{
    unsigned int state;        /* Some simple state information */
    pcap_t *input_adapter;
    pcap_t *output_adapter;
}in_out_adapters;

/* Prototypes */
DWORD WINAPI CaptureAndForwardThread(LPVOID lpParameter);
void ctrlc_handler(int sig);

/* This prevents the two threads to mess-up when they do printfs */
CRITICAL_SECTION print_cs;

/* Thread handlers. Global because we wait on the threads from the CTRL+C handler */
HANDLE threads[2];

/* This global variable tells the forwarder threads they must terminate */
volatile int kill_forwaders = 0;

/*******************************************************************/

#define IPTOSBUFFERS    12
char *iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    _snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]),"%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
    socklen_t sockaddrlen;

    #ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
    #else
    sockaddrlen = sizeof(struct sockaddr_storage);
    #endif


    if(getnameinfo(sockaddr, 
        sockaddrlen, 
        address, 
        addrlen, 
        NULL, 
        0, 
        NI_NUMERICHOST) != 0) address = NULL;

    return address;
}


int main()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum1, inum2;
    int i=0;
    pcap_t *adhandle1, *adhandle2;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask1, netmask2;
    char *packet_filter = {'\0'};
    char filter_file[MAX_PATH + 1] = {0};
    struct bpf_program fcode;
    in_out_adapters couple0;
    int fd;
    int readbytes;
    //char *packet_filter;
    char *comment;
    struct _stat buf;
    pcap_addr_t *addresses;
    char ip6str[128];

    /* 
    * Retrieve the device list 
    */

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. ", ++i);
        if (d->description)
            printf("%s \n\tDevice: (%s)\n", d->description, d->name);
        else
            printf("<unknown adapter> (%s)\n", d->name);

        /* IP addresses */
        for(addresses=d->addresses;addresses;addresses=addresses->next) {
            switch(addresses->addr->sa_family)
            {
            case AF_INET:
                if (addresses->addr)
                    printf("\tIPv4 Address: %s\n",iptos(((struct sockaddr_in *)addresses->addr)->sin_addr.s_addr));
                break;

            case AF_INET6:
                if (addresses->addr)
                    printf("\tIPv6 Address: %s\n", ip6tos(addresses->addr, ip6str, sizeof(ip6str)));
                break;

            default:
                printf("\tAddress Family Name: Unknown\n");
                break;
            }
        }
        printf("\n");

    }

    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }


    /*
    * Get input from the user
    */

    /* Get the filter*/
    printf("\nSpecify filter file(hit return for no filter):");

    fgets(filter_file, sizeof(filter_file), stdin);

    /*if(*filter_file != '\n' && -1 == (stat(filter_file, &buf) && _S_IFREG != buf.st_mode))
    {
    printf("Stat failed on %s: %s\n", filter_file, pcap_strerror(errno));
    return -1;
    }*/

    if (*filter_file != '\n')
    {
        filter_file[strlen(filter_file)-1] = 0; // clear off the trailing \n
        if(_sopen_s( &fd, filter_file, _O_RDONLY, _SH_DENYNO, _S_IREAD | _S_IWRITE ))
        {
            printf("\nUnable to open BPF filter file %s: %s\n", 
                filter_file, 
                pcap_strerror(errno));
            return -1;
        }

        if(_fstat(fd, &buf) < 0)
        {
            printf("Stat failed on %s: %s\n", filter_file, pcap_strerror(errno));
            return -1;
        }

        packet_filter = (char *)calloc((unsigned int)buf.st_size + 1, sizeof(unsigned char));

        if((readbytes = _read(fd, packet_filter, (int) buf.st_size)) < 0)
        {
            printf("Read failed on %s: %s\n", filter_file, pcap_strerror(errno));
            return -1;
        }

        if(readbytes != buf.st_size)
        {
            printf("Read bytes != file bytes on %s (%d != %d)\n",
                filter_file, readbytes, (int) buf.st_size);
            return -1;
        }

        packet_filter[(int)buf.st_size] = '\0';
        _close(fd);

        /* strip comments and <CR>'s */
        while((comment = strchr(packet_filter, '#')) != NULL)
        {
            while(*comment != '\r' && *comment != '\n' && comment != '\0')
            {
                *comment++ = ' ';
            }
        }
    }
    //packet_filter now contains the bpf filter

    /* Get the first interface number*/
    printf("\nEnter the number of the first interface to use (1-%d):",i);
    scanf_s("%d", &inum1);

    if(inum1 < 1 || inum1 > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Get the second interface number*/
    printf("Enter the number of the first interface to use (1-%d):",i);
    scanf_s("%d", &inum2);

    if(inum2 < 1 || inum2 > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    if(inum1 == inum2 )
    {
        printf("\nCannot bridge packets on the same interface.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }


    /*
    * Open the specified couple of adapters
    */

    /* Jump to the first selected adapter */
    for(d = alldevs, i = 0; i< inum1 - 1 ;d = d->next, i++);

    /* 
    * Open the first adapter.
    * *NOTICE* the flags we are using, they are important for the behavior of the prgram:
    *    - PCAP_OPENFLAG_PROMISCUOUS: tells the adapter to go in promiscuous mode.
    *    This means that we are capturing all the traffic, not only the one to or from
    *    this machine.
    *    - PCAP_OPENFLAG_NOCAPTURE_LOCAL: prevents the adapter from capturing again the packets
    *      transmitted by itself. This avoids annoying loops.
    *    - PCAP_OPENFLAG_MAX_RESPONSIVENESS: configures the adapter to provide minimum latency,
    *      at the cost of higher CPU usage.
    */
    if((adhandle1 = pcap_open(d->name,    // name of the device
        65536,                            // portion of the packet to capture. 
                                          // 65536 grants that the whole packet will be captured on every link layer.
        PCAP_OPENFLAG_PROMISCUOUS |       // flags. We specify that we don't want to capture loopback packets, and that the driver should deliver us the packets as fast as possible
        PCAP_OPENFLAG_NOCAPTURE_LOCAL |
        PCAP_OPENFLAG_MAX_RESPONSIVENESS,
        500,                              // read timeout
        NULL,                             // remote authentication
        errbuf                            // error buffer
        )) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->description);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    if(d->addresses != NULL)
    {
        /* Retrieve the mask of the first address of the interface */
        netmask1 = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    }
    else
    {
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask1 = 0xffffff; 
    }

    /* Jump to the second selected adapter */
    for(d = alldevs, i = 0; i< inum2 - 1 ;d = d->next, i++);

    /* Open the second adapter */
    if((adhandle2 = pcap_open(d->name,    // name of the device
        65536,                            // portion of the packet to capture. 
                                          // 65536 grants that the whole packet will be captured on every link layer.
        PCAP_OPENFLAG_PROMISCUOUS |       // flags. We specify that we don't want to capture loopback packets, and that the driver should deliver us the packets as fast as possible
        PCAP_OPENFLAG_NOCAPTURE_LOCAL |
        PCAP_OPENFLAG_MAX_RESPONSIVENESS,
        500,                             // read timeout
        NULL,                            // remote authentication
        errbuf                           // error buffer
        )) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->description);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    if(d->addresses != NULL)
    {
        /* Retrieve the mask of the first address of the interface */
        netmask2 = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    }
    else
    {
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask2 = 0xffffff; 
    }


    /*
    * Compile and set the filters
    */

    /* compile the filter for the first adapter */
    if (pcap_compile(adhandle1, &fcode, packet_filter, 1, netmask1) <0 )
    {
        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");

        /* Close the adapters */
        pcap_close(adhandle1);
        pcap_close(adhandle2);

        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* set the filter for the first adapter*/
    if (pcap_setfilter(adhandle1, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");

        /* Close the adapters */
        pcap_close(adhandle1);
        pcap_close(adhandle2);

        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* At this point, we don't need the device list any more. Free it */
    pcap_freealldevs(alldevs);

    /* 
    * Start the threads that will forward the packets 
    */

    /* Initialize the critical section that will be used by the threads for console output */
    InitializeCriticalSection(&print_cs);

    /* Init input parameters of the threads */
    couple0.state = 0;
    couple0.input_adapter = adhandle1;
    couple0.output_adapter = adhandle2;

    /* Start first thread */
    if((threads[0] = CreateThread(
        NULL,
        0,
        CaptureAndForwardThread,
        &couple0,
        0,
        NULL)) == NULL)
    {
        fprintf(stderr, "error creating the first forward thread");

        /* Close the adapters */
        pcap_close(adhandle1);
        pcap_close(adhandle2);

        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /*
    * Install a CTRL+C handler that will do the cleanups on exit
    */
    signal(SIGINT, ctrlc_handler);

    /* 
    * Done! 
    * Wait for the Greek calends... 
    */
    printf("\nStarted reflecting the adapter...\n", d->description);
    Sleep(INFINITE);
    return 0;
}

/*******************************************************************
* Forwarding thread.
* Gets the packets from the input adapter and sends them to the output one.
*******************************************************************/
DWORD WINAPI CaptureAndForwardThread(LPVOID lpParameter)
{
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int res = 0;
    in_out_adapters* ad_couple = lpParameter;
    unsigned __int64 n_fwd = 0;

    /*
    * Loop receiving packets from the first input adapter
    */

    while((!kill_forwaders) && (res = pcap_next_ex(ad_couple->input_adapter, &header, &pkt_data)) >= 0)
    {        
        if(res != 0)    /* Note: res=0 means "read timeout elapsed"*/
        {
#if _DEBUG
            /* 
            * Print something, just to show when we have activity.
            * BEWARE: acquiring a critical section and printing strings with printf
            * is something inefficient that you seriously want to avoid in your packet loop!    
            * However, since this DEBUG mode, we privilege visual output to efficiency.
            */
            EnterCriticalSection(&print_cs);

            if(ad_couple->state == 0)
                printf(">> Len: %u\n", header->caplen);
            else
                printf("<< Len: %u\n", header->caplen);        

            LeaveCriticalSection(&print_cs); 
#endif
            /*
            * Send the just received packet to the output adaper
            */
            if(pcap_sendpacket(ad_couple->output_adapter, pkt_data, header->caplen) != 0)
            {
                EnterCriticalSection(&print_cs);

                printf("Error sending a %u bytes packets on interface %u: %s\n",
                    header->caplen,
                    ad_couple->state,
                    pcap_geterr(ad_couple->output_adapter));

                LeaveCriticalSection(&print_cs); 
            }
            else
            {
                n_fwd++;
            }
        }
    }

    /*
    * We're out of the main loop. Check the reason.
    */
    if(res < 0)
    {
        EnterCriticalSection(&print_cs);

        printf("Error capturing the packets: %s\n", pcap_geterr(ad_couple->input_adapter));
        fflush(stdout);

        LeaveCriticalSection(&print_cs); 
    }
    else
    {
        EnterCriticalSection(&print_cs);

        printf("End of bridging on interface %u. Forwarded packets:%u\n",
            ad_couple->state,
            n_fwd);
        fflush(stdout);

        LeaveCriticalSection(&print_cs);
    }

    return 0;
}

/*******************************************************************
* CTRL+C hanlder.
* We order the threads to die and then we patiently wait for their
* suicide.
*******************************************************************/
void ctrlc_handler(int sig)
{
    /*
    * unused variable
    */
    (VOID)(sig);

    kill_forwaders = 1;

    WaitForMultipleObjects(2,
        threads,
        TRUE,        /* Wait for all the handles */
        5000);        /* Timeout */

    exit(0);
}