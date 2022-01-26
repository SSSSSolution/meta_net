#ifndef _META_NET_ISERVER_H_
#define _META_NET_ISERVER_H_

#include <string>
#include <memory>
#include <functional>
#include <atomic>

#include <WinSock2.h>
#include <WS2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

namespace meta_net
{

    struct NetAddress
    {
        std::string ipv4_addr;
        std::string port;
    };

    class IClientHandler
    {
    public:
        virtual NetAddress get_addr() = 0;
        virtual int set_timeout(int time_sec) = 0;
        virtual void send(const char *data, int len) = 0;
        virtual void close() = 0;
    };

    class TcpServerImpl;
    class TcpServer
    {
    public:
        TcpServer(NetAddress srv_addr, int thread_num);
        ~TcpServer();

        bool init();
        void listen();
        void close();

        virtual bool on_accept(IClientHandler *client_handle) {return true;}
        virtual void on_recv(IClientHandler *client_handle, const char *data, int len) {};
        virtual void on_close(IClientHandler *client_handle) {};
        virtual void on_abort() {};

    private:
        std::unique_ptr<TcpServerImpl> impl;
    };



}

#endif
