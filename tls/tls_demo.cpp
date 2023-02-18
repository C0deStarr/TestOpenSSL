#include "tls_demo.h"
#include "tls_ctx.h"

#include <iostream>
#include <string>

using namespace std;

void client(unsigned short port, char* ip)
{

}

void server(unsigned short port)
{
    TLS_CTX ctx;
    if (!ctx.InitServer("server.crt", "prikey.key"))
    {
        cout << "ctx.InitServer() failed£¡" << endl;
        getchar();
        return ;
    }
    cout << "ctx.InitServer() success£¡" << endl;

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