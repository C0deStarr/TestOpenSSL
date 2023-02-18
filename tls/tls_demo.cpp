#include "tls_demo.h"

#include <iostream>
#include <string>

using namespace std;

void client(unsigned short port, char* ip)
{

}

void server(unsigned short port)
{

}

void test_tls(int argc, char** argv)
{
    unsigned short port = 20300;
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