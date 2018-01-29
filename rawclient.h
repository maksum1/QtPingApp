#ifndef RAWCLIENT_H
#define RAWCLIENT_H


#include <iostream>
#include <winsock2.h>
#include <qdebug.h>
#include <qstring.h>

#define ICMP_ECHO_REPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_TTL_EXPIRE 11
#define ICMP_ECHO_REQUEST 8

// The IP header
struct IPHeader {
    BYTE h_len:4;           // Length of the header in dwords
    BYTE version:4;         // Version of IP
    BYTE tos;               // Type of service
    USHORT total_len;       // Length of the packet in dwords
    USHORT ident;           // unique identifier
    USHORT flags;           // Flags
    BYTE ttl;               // Time to live
    BYTE proto;             // Protocol number (TCP, UDP etc)
    USHORT checksum;        // IP checksum
    ULONG source_ip;
    ULONG dest_ip;
};

// ICMP header
struct ICMPHeader {
    BYTE type;          // ICMP packet type
    BYTE code;          // Type sub code
    USHORT checksum;
    USHORT id;
    USHORT seq;
    ULONG timestamp;    // not part of ICMP, but I need it foe check
};


class RawClient
{
public:
    //Set packet_size to default size = 32
    //Set ttl to default = 30
    RawClient(char *Host_Name);

private:
    void ping();


    // Fill in the fields and data area of an ICMP packet, making it
    // packet_size bytes by padding it with a byte pattern, and giving it
    // the given sequence number.  That completes the packet, so we also
    // calculate the checksum for the packet and place it in the appropriate
    // field.
    int setup_for_ping();

    // Send an ICMP echo ("ping") packet to host dest by way of sd with
    // packet_size bytes.  packet_size is the total size of the ping packet
    // to send, including the ICMP header and the payload area; it is not
    // checked for sanity, so make sure that it's at least
    // sizeof(ICMPHeader) bytes, and that send_buf points to at least
    // packet_size bytes.  Returns < 0 for failure.
    int send_ping();

    // Receive a ping reply on sd into recv_buf, and stores address info
    // for sender in source.  On failure, returns < 0, 0 otherwise.
    //
    // Note that recv_buf must be larger than send_buf (passed to send_ping)
    // because the incoming packet has the IP header attached.  It can also
    // have IP options set, so it is not sufficient to make it
    // sizeof(send_buf) + sizeof(IPHeader).  We suggest just making it
    // fairly large and not worrying about wasting space.
    int recv_ping();

    // Decode and output details about an ICMP reply packet.  Returns -1
    // on failure, -2 on "try again" and 0 on success.
    int decode_reply(IPHeader* reply, int bytes, sockaddr_in* from);

    //create ip checksum
    USHORT ip_checksum(USHORT* buffer, int size);

    char* m_host_name;

    const int m_MAX_PING_DATA_SIZE;
    const int m_MAX_PING_PACKET_SIZE;

    int m_packet_size;
    int m_ttl;

    ICMPHeader* m_send_buf;
    IPHeader* m_recv_buf;

    SOCKET m_sd;
    sockaddr_in m_dest;
    sockaddr_in m_source;


};

#endif // RAWCLIENT_H

