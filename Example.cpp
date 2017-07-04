#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#pragma comment(lib, "ws2_32")

void connect_wsa()
{
	WSADATA wsaData;
	char buf[8192] = {};
	WSABUF DataBuf;
	DataBuf.buf = buf;

	WSAStartup(MAKEWORD(2, 2), &wsaData);
	SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, 0);

	struct addrinfo *result;
	getaddrinfo("www.example.com", "http", NULL, &result);

	int ret = WSAConnect(s, result->ai_addr, sizeof(SOCKADDR), NULL, NULL, NULL, NULL);
	if (ret == SOCKET_ERROR) {
		closesocket(s);
		WSACleanup();
		return;
	}

	strcpy(buf, "GET / HTTP/1.0\r\nHost: www.example.com\r\n\r\n");
	DataBuf.len = strlen(buf);
	WSASend(s, &DataBuf, 1, NULL, 0, NULL, NULL);

	Sleep(1000);

	DWORD Flags = 0;
	DataBuf.len = 8192;
	WSARecv(s, &DataBuf, 1, NULL, &Flags, NULL, NULL);
	puts(DataBuf.buf);

	closesocket(s);
	WSACleanup();
}

void connect_posix()
{
	WSADATA wsaData;
	char buf[8192] = {};

	WSAStartup(MAKEWORD(2, 2), &wsaData);
	SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, 0);

	SOCKADDR_IN name;
	name.sin_family = AF_INET;
	name.sin_addr.s_addr = *(u_long *)gethostbyname("www.example.com")->h_addr_list[0];
	name.sin_port = htons(80);

	int ret = connect(s, (SOCKADDR *)&name, sizeof(name));
	if (ret == SOCKET_ERROR) {
		closesocket(s);
		WSACleanup();
		return;
	}

	strcpy(buf, "GET / HTTP/1.0\r\nHost: www.example.com\r\n\r\n");
	send(s, buf, strlen(buf), 0);

	Sleep(1000);

	recv(s, buf, 8192, 0);
	puts(buf);

	closesocket(s);
	WSACleanup();
}

void do_inet_addr()
{
	int addr = inet_addr("192.168.0.1");
	printf("%x\n", addr);
}

int main()
{
	connect_wsa();
	connect_posix();
	do_inet_addr();
	return 0;
}
