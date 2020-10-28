#pragma once

Mac GetMacFromIP(pcap_t* handle, Ip ipAddr);
Mac GetMyMacAddr(const char* ifname);
Ip GetMyIp(const char* ifname);