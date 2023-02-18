#include "tls_demo.h"
#include "tls_ctx.h"

#include <iostream>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace std;

void client(unsigned short port, char* ip)
{

}

void server(unsigned short port)
{
    TLS_CTX ctx;
    MySSL ssl;
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
        
    }
}

void test_tls(int argc, char** argv)
{
    unsigned short port = 23333;
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