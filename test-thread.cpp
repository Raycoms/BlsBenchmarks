#include <iostream>
#include <bls.hpp>
#include <random>
#include <pthread.h>
#include <thread>
#include <atomic>

using namespace bls;
using namespace std;

const size_t N = 100;
const size_t Threads = 10;

atomic_int counter(0);

struct ThreadData
{
    int index;
    int count;

    ThreadData(const int index, const int count): index(index), count(count){};
};

void executeSlave(ThreadData my_data)
{
    for( int x = my_data.index; x < my_data.index + my_data.count; x++ )
    {
        cout << "Thread: " << my_data.index <<  ": " << x << endl;

        auto start = std::chrono::steady_clock::now();

        int i = 0;

        while (i++ < 100000)
        {
            for (int y = 0; y < 1000; y++)
            {
                sqrt(y);
            }
        }

        auto end = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed_seconds = end - start;
        cout << "Time: " << elapsed_seconds.count() << endl;
    }

    counter.fetch_add(my_data.count);

    pthread_exit(NULL);
}

int main()
{
    auto start = std::chrono::steady_clock::now();

    int each = N / Threads;
    cout << each << endl;
    for (int x = 0; x < Threads; x++)
    {
        cout << "main() : creating thread, " << x << endl;

        std::thread th (executeSlave, ThreadData(x * each, each));
        th.detach();
    }

    while (counter < N)
    {
        std::this_thread::sleep_for(10ms);
    }

    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed_seconds = end - start;

    cout << "Final:" << endl;
    cout << elapsed_seconds.count() << endl;

}
