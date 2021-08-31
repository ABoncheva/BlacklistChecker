#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "ws2_32.lib")
#define MAX_IP_LEN 16
#define DIGITS_IN_OCTET 3

#include <iostream>
#include<WS2tcpip.h>
#include<string>
#include <vector>
#include<algorithm>


void tokenize(std::vector<std::string>& tokens, const std::string& ip)
{
	size_t start;
	size_t end = 0;
	while ((start = ip.find_first_not_of('.', end)) != std::string::npos)
	{
		end = ip.find('.', start);
		tokens.push_back(ip.substr(start, end - start));
	}
}

std::string reverseIP(std::string& ip)
{
	std::vector<std::string> octets;
	std::string reversedIP;
	tokenize(octets, ip);
	for (auto i = octets.rbegin(); i != octets.rend(); ++i)
		reversedIP = reversedIP + *i + '.';

	reversedIP = reversedIP.substr(0, reversedIP.length() - 1);
	return reversedIP;
}

unsigned short getLastOctet(const in_addr& ip)
{
	char textIP[MAX_IP_LEN + 1];
	inet_ntop(AF_INET, &ip, textIP, MAX_IP_LEN + 1);

	std::string temp(textIP);
	temp = temp.substr(temp.length() - DIGITS_IN_OCTET, DIGITS_IN_OCTET);
	temp.erase(std::remove(temp.begin(), temp.end(), '.'), temp.end());
	return std::stoi(temp);
}

void getBlackListedInfo(const in_addr& ip)
{
	char textIP[MAX_IP_LEN + 1];
	inet_ntop(AF_INET, &ip, textIP, MAX_IP_LEN + 1);

	unsigned short lastOctet = getLastOctet(ip);

	if (lastOctet == 2)
		std::cout << "'" << textIP << " - SBL - Spamhaus SBL Data'" << std::endl;
	if (lastOctet == 3)
		std::cout << "'" << textIP << " - SBL - Spamhaus SBL CSS Data'" << std::endl;
	if (lastOctet == 4)
		std::cout << "'" << textIP << " - XBL - CBL Data'" << std::endl;
	if (lastOctet == 9)
		std::cout << "'" << textIP << " - SBL - Spamhaus DROP/EDROP Data'" << std::endl;
	if (lastOctet == 10)
		std::cout << "'" << textIP << " - PBL - ISP Maintained'" << std::endl;
	if (lastOctet == 11)
		std::cout << "'" << textIP << " - PBL - Spamhaus Maintained'" << std::endl;
}

void getInput(std::vector<std::string>& IPs)
{
	std::string input;
	std::cin >> input;
	while (input != "exit")
	{
		IPs.push_back(input);
		std::cin >> input;
	}
}

void checkIPs(std::vector<std::string>& IPs)
{
	struct in_addr address;
	std::string hostName;
	struct hostent* remoteHost;

	for (auto i = 0; i < IPs.size(); ++i)
	{
		std::string reversedIP = reverseIP(IPs[i]);
		hostName = reversedIP + ".zen.spamhaus.org";
		remoteHost = gethostbyname(hostName.c_str());

		if (remoteHost == nullptr)
			std::cout << "The IP address: " << IPs[i] << " is not blacklisted." << std::endl;
		else
		{
			unsigned counter = 0;
			std::cout << "The IP address: " << IPs[i] << " is found in the following Spamhaus public IP zone:" << std::endl;
			while (remoteHost->h_addr_list[counter] != 0)
			{
				address.s_addr = *(u_long*)remoteHost->h_addr_list[counter];
				getBlackListedInfo(address);
				++counter;
			}
		}
	}
}
int main()
{
	WSADATA wsaData;
	int initRes;

	initRes = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (initRes != 0)
	{
		std::cout << "Startup not successful! " << initRes << std::endl;
		return 1;
	}

	std::vector<std::string> IPs;
	getInput(IPs);
	checkIPs(IPs);

	return 0;
}