#include "tls_demo.h"
#include "tls_ctx.h"

#include <iostream>
#include <string>
#include <sstream>
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

using namespace std;

void client(unsigned short port, char* ip)
{
    string strIp = ip;
    TLS_CTX ctx;
    int nRet = 0;
    sockaddr_in sa = {0};
    int sock = 0;
    MySSL myssl;
    string data = "Client : ";

    if (!ctx.InitClient("server.crt", "cacert.pem"))
    {
        return ;
    }
    do {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        sa.sin_family = AF_INET;
        inet_pton(sa.sin_family, strIp.c_str(), &(sa.sin_addr.s_addr));
        //sa.sin_addr.s_addr = inet_addr(strIp.c_str());
        sa.sin_port = htons(port);
        nRet = connect(sock, (sockaddr*)&sa, sizeof(sa));
        if (0 != nRet)
        {
            cout << "connect " << ip << ":" << port << " faield!" << endl;
            break;
        }
        cout << "connect " << ip << ":" << port << " success!" << endl;

        if(!ctx.InitSSL(sock, myssl))
        {
            cout << "InitSSL() err" << endl;
            break;
        }
        if (!myssl.Connect())
        {
            cout << "Connect() err" << endl;
            break;
        }

        // read/write
        for (int i = 0; i < 10; i++)
        {
            stringstream ss;
            ss << data;
            ss << i;
            int len = myssl.Write(ss.str().c_str(), ss.str().size());
            if (len <= 0)
                break;
            char buf[1024] = { 0 };
            len = myssl.Read(buf, sizeof(buf) - 1);
            if (len > 0)
                cout << buf << endl;

            this_thread::sleep_for(chrono::seconds(1));
        }

        myssl.Close();
    }while(0);

    
}

void server(unsigned short port)
{
    TLS_CTX ctx;
    MySSL ssl;
    string data = "Server : ";

    if (!ctx.InitServer("server.crt", "prikey.key"))
    {
        cout << "ctx.InitServer() failed£¡" << endl;
        getchar();
        return ;
    }
    cout << "ctx.InitServer() success£¡" << endl;


    // socket
    int accept_sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in sa_server;
    memset(&sa_server, 0, sizeof(sa_server));
    sa_server.sin_family = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port = htons(port);
    int re = ::bind(accept_sock, (sockaddr*)&sa_server, sizeof(sa_server));
    if (re != 0)
    {
        cerr << " bind port:" << port << " failed!" << endl;
        getchar();
    }
    listen(accept_sock, 10);
    cout << "start listen port " << port << endl;


    while (1)
    {
        int socketClient = accept(accept_sock, 0, 0);
        if (socketClient <= 0)
            break;
        cout << "accept socket" << endl;
        
        if (!ctx.InitSSL(socketClient, ssl))
        {
            cout << "InitSSL() err" << endl;
            continue;
        }
        if (!ssl.Accept())
        {
            ssl.Close();
            continue;
        }


        // read/write
        for (int i = 0; i < 10; i++)
        {
            stringstream ss;
            ss << data;
            ss << i;
            int len = ssl.Write(ss.str().c_str(), ss.str().size());
            if (len <= 0)
                break;
            char buf[1024] = { 0 };
            len = ssl.Read(buf, sizeof(buf) - 1);
            if (len > 0)
                cout << buf << endl;

            this_thread::sleep_for(chrono::seconds(1));
        }

        ssl.Close();
        
    }
    
}

void test_tls(int argc, char** argv)
{
    unsigned short port = 23333;

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    if (argc > 1)
    {
        port = atoi(argv[1]);
    }

    do {

        if (argc > 2)
        {
            // client
            // EXE PORT IP
            client(port, argv[2]);
            break;
        }
        server(port);
    }while(0);

    getchar();
    return;
}