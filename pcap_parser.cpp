#include <napi.h>
#include <pcap.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

using namespace Napi;

struct PacketInfo {
    std::string src_ip;
    std::string dst_ip;
    int src_port;
    int dst_port;
    std::string protocol;
    std::string payload;
};

// Função para imprimir o payload no formato ASCII
std::string to_ascii(const u_char* data, size_t len) {
    std::stringstream ss;
    for (size_t i = 0; i < len; ++i) {
        if (isprint(data[i])) {
            ss << data[i];  // Adiciona o caractere se for imprimível
        } else {
            ss << ".";  // Substitui caracteres não imprimíveis por ponto
        }
    }
    return ss.str();
}

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    std::vector<PacketInfo>* packets = reinterpret_cast<std::vector<PacketInfo>*>(user);

    if (header->caplen < 14) {
        // Não há dados suficientes para um cabeçalho Ethernet válido
        return;
    }

    struct ip *ip_header = (struct ip *)(packet + 14);  // Ajuste do offset para o cabeçalho IP

    // Verifique se o cabeçalho IP é válido
    if (header->caplen < 14 + ip_header->ip_hl * 4) {
        // Não há dados suficientes para o cabeçalho IP completo
        return;
    }

    PacketInfo info;
    info.src_ip = inet_ntoa(ip_header->ip_src);
    info.dst_ip = inet_ntoa(ip_header->ip_dst);

    // Checa o tipo de protocolo (TCP/UDP) ou outro
    if (ip_header->ip_p == IPPROTO_TCP) {
        if (header->caplen < 14 + ip_header->ip_hl * 4 + sizeof(struct tcphdr)) {
            return;  // Não há espaço suficiente para o cabeçalho TCP
        }
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header->ip_hl * 4);
        info.src_port = ntohs(tcp_header->th_sport);
        info.dst_port = ntohs(tcp_header->th_dport);
        info.protocol = "TCP";
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        if (header->caplen < 14 + ip_header->ip_hl * 4 + sizeof(struct udphdr)) {
            return;  // Não há espaço suficiente para o cabeçalho UDP
        }
        struct udphdr *udp_header = (struct udphdr *)(packet + 14 + ip_header->ip_hl * 4);
        info.src_port = ntohs(udp_header->uh_sport);
        info.dst_port = ntohs(udp_header->uh_dport);
        info.protocol = "UDP";
    } else {
        info.protocol = "OTHER";
        info.src_port = 0;
        info.dst_port = 0;
    }

    // Verifique se o pacote tem bytes suficientes para o payload
    size_t payload_offset = 14 + ip_header->ip_hl * 4;  // Offset do payload
    if (header->caplen < payload_offset) {
        return;  // Não há dados suficientes para o payload
    }

    size_t payload_len = header->caplen - payload_offset;
    info.payload = to_ascii(packet + payload_offset, payload_len);

    packets->push_back(info);
}

Value ParsePcap(const CallbackInfo& info) {
    Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsString()) {
        TypeError::New(env, "Argument must be a string (path to .pcap or .pcapng file)").ThrowAsJavaScriptException();
        return env.Null();
    }
    std::string filename = info[0].As<String>().Utf8Value();
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename.c_str(), errbuf);

    if (handle == NULL) {
        TypeError::New(env, "Error opening file: " + std::string(errbuf)).ThrowAsJavaScriptException();
        return env.Null();
    }

    std::vector<PacketInfo> packets;
    pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(&packets));
    pcap_close(handle);

    Array result = Array::New(env, packets.size());
    for (size_t i = 0; i < packets.size(); ++i) {
        Object obj = Object::New(env);
        obj.Set("src_ip", packets[i].src_ip);
        obj.Set("dst_ip", packets[i].dst_ip);
        obj.Set("src_port", packets[i].src_port);
        obj.Set("dst_port", packets[i].dst_port);
        obj.Set("protocol", packets[i].protocol);
        obj.Set("payload", packets[i].payload);
        result.Set(i, obj);
    }

    return result;
}

Object Init(Env env, Object exports) {
    exports.Set("parsePcap", Function::New(env, ParsePcap));
    return exports;
}

NODE_API_MODULE(pcap_parser, Init)
