#include "meta_net/IServer.h"
#include <iostream>
#include <list>

namespace meta_net
{

    enum IoType
    {
        RECV,
        SEND,
    };

    struct IOContext
    {
        WSAOVERLAPPED overlapped;
        SOCKET socket;
        WSABUF wsa_buf;
        char buffer[8192];
        DWORD flags;

        int bytes_to_send = 0;
        int bytes_sent = 0;

        IoType io_type;
    };

    // class ClientHandler
    class ClientHandler : public IClientHandler
    {
    public:
        ClientHandler(SOCKET socket, TcpServer *server);
        virtual ~ClientHandler();

        virtual NetAddress get_addr() override;
        virtual int set_timeout(int time_sec) override;
        virtual void send(const char *data, int len) override;
        virtual void close() override;

        SOCKET socket();
        TcpServer *server();

    private:
        SOCKET m_socket;
        TcpServer *m_server;
    };

    ClientHandler::ClientHandler(SOCKET socket, TcpServer *server)
        : m_socket(socket), m_server(server)
    {}

    ClientHandler::~ClientHandler()
    {}

    NetAddress ClientHandler::get_addr()
    {
        sockaddr_in client_addr = {0};
        int name_len;

        getpeername(m_socket, (struct sockaddr *)&client_addr, &name_len);
        char ip[128] = {0};
        inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
        int port = ntohs(client_addr.sin_port);

        NetAddress addr;
        addr.ipv4_addr = std::string(ip);
        addr.port = std::to_string(port);

        return addr;
    }

    int ClientHandler::set_timeout(int time_sec)
    {
        return 0;
    }

    void ClientHandler::send(const char *data, int len)
    {

    }

    void ClientHandler::close()
    {
        closesocket(m_socket);
    }

    SOCKET ClientHandler::socket()
    {
        return m_socket;
    }

    TcpServer *ClientHandler::server()
    {
        return m_server;
    }

    static DWORD WINAPI ServerWorkerThread(LPVOID lpParameter)
    {
        HANDLE hCompletionPort = (HANDLE)lpParameter;
        DWORD NumBytesTrans = 0;
        IOContext *io_context;
        ClientHandler *client_handle;

        while (GetQueuedCompletionStatus(hCompletionPort, &NumBytesTrans, (PULONG_PTR)(&client_handle), (LPOVERLAPPED *)&io_context, 1000) ||
               (io_context != nullptr))
        {
            if (!io_context)
            {
                continue;
            }

            if (NumBytesTrans == 0)
            {
                std::cout << "client disconnected!" << std::endl;
            }
            else if (io_context->io_type == RECV)
            {
                client_handle->server()->on_recv(client_handle, io_context->buffer, (int)NumBytesTrans);
                io_context->wsa_buf.len = sizeof(io_context->buffer);
                io_context->flags = 0;

                int ret = WSARecv(client_handle->socket(), &(io_context->wsa_buf), 1, &NumBytesTrans,
                                  &(io_context->flags), &(io_context->overlapped), nullptr);
                if (ret == 0)
                {
                    continue;
                }
                else
                {
                    if (WSAGetLastError() == WSA_IO_PENDING)
                    {
                        continue;
                    }
                    else
                    {
                        std::cout << "Recv Error: " << WSAGetLastError() << std::endl;
                    }
                }
            }
            else if (io_context->io_type == SEND)
            {
                io_context->bytes_sent += NumBytesTrans;
                if (io_context->bytes_sent < io_context->bytes_to_send)
                {
                    io_context->wsa_buf.buf = io_context->buffer + io_context->bytes_sent;
                    io_context->wsa_buf.len = io_context->bytes_to_send - io_context->bytes_sent;
                }

                int ret = WSASend(client_handle->socket(), &(io_context->wsa_buf), 1, nullptr,
                                  io_context->flags, &(io_context->overlapped), nullptr);
                if (ret == 0)
                {
                    continue;
                }
                else
                {
                    if (WSAGetLastError() == WSA_IO_PENDING)
                    {
                        continue;
                    }
                    else
                    {
                        std::cout << "Send Error: " << WSAGetLastError() << std::endl;
                    }
                }
            }

            delete io_context;
            client_handle->close();
            delete client_handle;
        }

        return 0;
    }


    // class TcpServer

    class TcpServerImpl
    {
    public:
        TcpServerImpl(TcpServer *srv)
        {
            server = srv;
        }

        TcpServer *server;
        std::function<void (std::shared_ptr<ClientHandler>)> accept_client_cb;
        HANDLE hCompletionPort;
        NetAddress addr;
        SOCKET listen_socket;

        int thread_num;

        void on_accept(SOCKET accept_socket)
        {
            auto client_handle = new ClientHandler(accept_socket, server);
            if (!server->on_accept(client_handle))
            {
                client_handle->close();
                delete client_handle;
                return;
            }

            CreateIoCompletionPort(reinterpret_cast<HANDLE>(accept_socket), hCompletionPort,
                                   reinterpret_cast<ULONG_PTR>(client_handle), 0);

            auto io_context = new IOContext();
            io_context->wsa_buf.buf = io_context->buffer;
            io_context->wsa_buf.len = 8192;
            io_context->io_type = RECV;

            int ret = WSARecv(accept_socket, &(io_context->wsa_buf), 1, nullptr,
                              &(io_context->flags), &(io_context->overlapped), nullptr);
            if (ret != 0)
            {
                if (WSAGetLastError() != WSA_IO_PENDING)
                {
                    std::cout << "Error: " << WSAGetLastError();
                    delete io_context;
                    client_handle->close();
                    delete client_handle;
                    return;
                }
            }
        }
    };

    TcpServer::TcpServer(NetAddress srv_addr, int thread_num)
        : impl(std::make_unique<TcpServerImpl>(this))
    {
        impl->addr = srv_addr;
        impl->thread_num = thread_num;
    }

    TcpServer::~TcpServer()
    {}

    bool TcpServer::init()
    {
        // 1. init Winsock
        WSADATA wsaData;

        int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (ret != 0)
        {
            return false;
        }

        impl->hCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, (DWORD)(impl->thread_num));
        if (!impl->hCompletionPort)
        {
            return false;
        }

        SYSTEM_INFO system_info;
        GetSystemInfo(&system_info);

        for (DWORD i = 0; i < system_info.dwNumberOfProcessors; ++i)
        {
            HANDLE thread = CreateThread(nullptr, 0, ServerWorkerThread, impl->hCompletionPort, 0, nullptr);
            CloseHandle(thread);
        }

        // 2. create socket for server
        struct addrinfo *result = nullptr, *ptr = nullptr, hints;
        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_INET; // IPV4 address family
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = AI_PASSIVE;

        ret = getaddrinfo(nullptr, impl->addr.port.c_str(), &hints, &result);
        if (ret != 0)
        {
            WSACleanup();
            return false;
        }

        impl->listen_socket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (impl->listen_socket == INVALID_SOCKET)
        {
            WSACleanup();
            return false;
        }

        // bind socket
        ret = bind(impl->listen_socket, result->ai_addr, (int)result->ai_addrlen);
        if (ret == SOCKET_ERROR)
        {
            closesocket(impl->listen_socket);
            WSACleanup();
            return false;
        }

        freeaddrinfo(result);

        return true;
    }

    void TcpServer::listen()
    {
        if (::listen(impl->listen_socket, SOMAXCONN) == SOCKET_ERROR)
        {
            closesocket(impl->listen_socket);
            WSACleanup();
            return;
        }

        bool stop = false;
        while (!stop)
        {
            SOCKET accept_socket =accept(impl->listen_socket, nullptr, nullptr);
            if (accept_socket == INVALID_SOCKET)
            {
                switch (WSAGetLastError())
                {
                case WSANOTINITIALISED:
                    throw std::runtime_error("A successful WSAStartup call must occur before using this function!");
                    break;
                case WSAECONNRESET:
                    // todo something
                    std::cout << "WSANOTINITIALISED" << std::endl;
                    continue;
                case WSAEFAULT:
                    throw std::runtime_error("The addrlen parameter is too small or addr is not a valid part of the user address space!");
                    break;
                case WSAEINTR:
                    // todo close
                    std::cout << "WSAEINTR" << std::endl;
                    std::cout << "stop listen" << std::endl;
                    stop = true;
                    continue;
                case WSAEINVAL:
                    throw std::runtime_error("The listen function was not invoked prior to accept!");
                    break;
                case WSAEINPROGRESS:
                    throw std::runtime_error("WSAEINPROGRESS!");
                    break;
                case WSAEMFILE:
                    throw std::runtime_error("Too many open sockets!");
                    break;
                case WSAENETDOWN:
                    throw std::runtime_error("The network subsystem has failed!");
                    break;
                case WSAENOBUFS:
                    throw std::runtime_error("No buffer space is available!");
                    break;
                case WSAENOTSOCK:
                    throw std::runtime_error("The descriptor is not a socket!");
                    break;
                case WSAEOPNOTSUPP:
                    throw std::runtime_error("The referenced socket is not a type that supports connection-oriented service!");
                    break;
                case WSAEWOULDBLOCK:
                    // todo close ?
                    std::cout << "WSAEWOULDBLOCK" << std::endl;
                    break;
                default:
                    break;
                }
            }
            impl->on_accept(accept_socket);
        }
    }

    void TcpServer::close()
    {
        closesocket(impl->listen_socket);
    }

}


