#include "rawclient.h"

RawClient::RawClient(char *Host_Name): packet_size(32), m_ttl(30), MAX_PING_DATA_SIZE(1024),
    MAX_PING_PACKET_SIZE(MAX_PING_DATA_SIZE + sizeof(IPHeader)), m_host_name(Host_Name)
{
    m_packet_size = max(sizeof(ICMPHeader),
                min(1024, (unsigned int)packet_size));
    //Initialise Winsock
    WSADATA wsock;
    printf("\nInitialising Winsock...");
    if (WSAStartup(MAKEWORD(2,2),&wsock) != 0)
    {
    qDebug()<<"WSAStartup() failed";
    }
    qDebug()<<"Initialised successfully.";

    // First the send buffer
    m_send_buf = (ICMPHeader*)new char[packet_size];
    // And then the receive buffer
    m_recv_buf = (IPHeader*)new char[MAX_PING_PACKET_SIZE];
}

void RawClient::ping(char *Host_Name)
{
     = Host_Name;
    if (setup_for_ping() < 0)
    {
         qDebug()<<"Bad setup.";
    }

    init_ping_packet();

        // Send the ping and receive the reply
        if (send_ping() >= 0) {
            while (1) {
                // Receive replies until we either get a successful read,
                // or a fatal error occurs.
                if (recv_ping() < 0) {
                    // Pull the sequence number out of the ICMP header.  If
                    // it's bad, we just complain, but otherwise we take
                    // off, because the read failed for some reason.
                    unsigned short header_len = recv_buf->h_len * 4;
                    ICMPHeader* icmphdr = (ICMPHeader*)
                            ((char*)recv_buf + header_len);
                    if (icmphdr->seq != seq_no) {
                        cerr << "bad sequence number!" << endl;
                        continue;
                    }
                    else {
                        break;
                    }
                }
                if (decode_reply() != -2) {
                    // Success or fatal error (as opposed to a minor error)
                    // so take off.
                    break;
                }
            }
        }
}

int RawClient::setup_for_ping()
{
    // Create the socket
    sd = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, 0, 0, 0);
    if (sd == INVALID_SOCKET) {
        cerr << "Failed to create raw socket: " << WSAGetLastError() <<
                endl;
        return -1;
    }

    if (setsockopt(m_sd, IPPROTO_IP, IP_TTL, (const char*)&m_ttl,
            sizeof(m_ttl)) == SOCKET_ERROR) {
        cerr << "TTL setsockopt failed: " << WSAGetLastError() << endl;
        return -1;
    }

    // Initialize the destination host info block
    memset(&m_dest, 0, sizeof(m_dest));

    // Turn first passed parameter into an IP address to ping
    unsigned int addr = inet_addr(m_host_name);
    if (addr != INADDR_NONE) {
        // It was a dotted quad number, so save result
        dest.sin_addr.s_addr = addr;
        dest.sin_family = AF_INET;
    }
    else {
        // Not in dotted quad form, so try and look it up
        hostent* hp = gethostbyname(m_host_name);
        if (hp != 0) {
            // Found an address for that host, so save it
            memcpy(&(m_dest.sin_addr), hp->h_addr, hp->h_length);
            m_dest.sin_family = hp->h_addrtype;
        }
        else {
            // Not a recognized hostname either!
            cerr << "Failed to resolve " << host << endl;
            return -1;
        }
    }

    return 0;
}

void RawClient::init_ping_packet()
{
    // Set up the packet's fields
    m_send_buf->type = ICMP_ECHO_REQUEST;
    m_send_buf->code = 0;
    m_send_buf->checksum = 0;
    m_send_buf->id = (USHORT)GetCurrentProcessId();
    m_send_buf->seq = 0;
    m_send_buf->timestamp = GetTickCount();

    // "You're dead meat now, packet!"
    const unsigned long int deadmeat = 0xDEADBEEF;
    char* datapart = (char*)m_send_buf + sizeof(ICMPHeader);
    int bytes_left = m_packet_size - sizeof(ICMPHeader);
    while (bytes_left > 0) {
        memcpy(datapart, &deadmeat, min(int(sizeof(deadmeat)),
                bytes_left));
        bytes_left -= sizeof(deadmeat);
        datapart += sizeof(deadmeat);
    }

    // Calculate a checksum on the result
    m_send_buf->checksum = ip_checksum((USHORT*)m_send_buf, m_packet_size);
}

int RawClient::send_ping()
{
    // Send the ping packet in send_buf as-is
    cout << "Sending " << m_packet_size << " bytes to " <<
            inet_ntoa(m_dest.sin_addr) << "..." << flush;
    int bwrote = sendto(m_sd, (char*)m_send_buf, packet_size, 0,
            (sockaddr*)&m_dest, sizeof(m_dest));
    if (bwrote == SOCKET_ERROR) {
        cerr << "send failed: " << WSAGetLastError() << endl;
        return -1;
    }
    else if (bwrote < m_packet_size) {
        cout << "sent " << bwrote << " bytes..." << flush;
    }

    return 0;
}


int RawClient::recv_ping()
{
    // Wait for the ping reply
    int fromlen = sizeof(m_source);
    int bread = recvfrom(m_sd, (char*)m_recv_buf,
            m_packet_size + sizeof(IPHeader), 0,
            (sockaddr*)&m_source, &fromlen);
    if (bread == SOCKET_ERROR) {
        cerr << "read failed: ";
        if (WSAGetLastError() == WSAEMSGSIZE) {
            cerr << "buffer too small" << endl;
        }
        else {
            cerr << "error #" << WSAGetLastError() << endl;
        }
        return -1;
    }

    return 0;
}



int RawClient::decode_reply()
{
    // Skip ahead to the ICMP header within the IP packet
    unsigned short header_len = m_recv_buf->h_len * 4;
    ICMPHeader* icmphdr = (ICMPHeader*)((char*)m_recv_buf + header_len);

    // Make sure the reply is sane
    if (m_packet_size < header_len + ICMP_MIN) {
        cerr << "too few bytes from " << inet_ntoa(m_source->sin_addr) <<
                endl;
        return -1;
    }
    else if (icmphdr->type != ICMP_ECHO_REPLY) {
        if (icmphdr->type != ICMP_TTL_EXPIRE) {
            if (icmphdr->type == ICMP_DEST_UNREACH) {
                cerr << "Destination unreachable" << endl;
            }
            else {
                cerr << "Unknown ICMP packet type " << int(icmphdr->type) <<
                        " received" << endl;
            }
            return -1;
        }
        // If "TTL expired", fall through.  Next test will fail if we
        // try it, so we need a way past it.
    }
    else if (icmphdr->id != (USHORT)GetCurrentProcessId()) {
        // Must be a reply for another pinger running locally, so just
        // ignore it.
        return -2;
    }

    // Figure out how far the packet travelled
    int nHops = int(256 - m_recv_buf->ttl);
    if (nHops == 192) {
        // TTL came back 64, so ping was probably to a host on the
        // LAN -- call it a single hop.
        nHops = 1;
    }
    else if (nHops == 128) {
        // Probably localhost
        nHops = 0;
    }

    // Okay, we ran the gamut, so the packet must be legal -- dump it
    cout << endl << m_packet_size << " bytes from " <<
            inet_ntoa(m_source->sin_addr) << ", icmp_seq " <<
            icmphdr->seq << ", ";
    if (icmphdr->type == ICMP_TTL_EXPIRE) {
        cout << "TTL expired." << endl;
    }
    else {
        cout << nHops << " hop" << (nHops == 1 ? "" : "s");
        cout << ", time: " << (GetTickCount() - icmphdr->timestamp) <<
                " ms." << endl;
    }

    return 0;
}

USHORT RawClient::ip_checksum(USHORT *buffer, int size)
{
    unsigned long cksum = 0;

    // Sum all the words together, adding the final byte if size is odd
    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(USHORT);
    }
    if (size) {
        cksum += *(UCHAR*)buffer;
    }

    // Do a little shuffling
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);

    // Return the bitwise complement of the resulting mishmash
    return (USHORT)(~cksum);
}
