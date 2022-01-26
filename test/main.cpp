#include <meta_net/IServer.h>
#include <thread>

using namespace meta_net;

int main(int argc, char **argv)
{
    NetAddress addr;
    addr.ipv4_addr = "127.0.0.1";
    addr.port = "1234";
    TcpServer server(addr);

    std::thread t1([&](){
        std::this_thread::sleep_for(std::chrono::seconds(3));
//        server.close();
    });

    server.init();
    server.listen();

    t1.join();
    return 0;
}
