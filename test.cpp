#include <iostream>
#include <bls.hpp>
#include <random>
#include <pthread.h>
#include <thread>
#include <atomic>
#include <mutex>

using namespace bls;
using namespace std;

const size_t K = 35;
const size_t N = 50;
const size_t Threads = 10;
const bool threaded = true;

atomic_int counter(0);
vector<PublicKey> pubs;

vector<InsecureSignature> sigShareIn;

uint8_t theHash[32];

size_t *playersArr[N];
InsecureSignature *sigShareOutArr[N];

struct ThreadData
{
    int index;
    int count;

    ThreadData(const int index, const int count): index(index), count(count){};
};

void *executeSlave(void *threadarg)
{
    //clock_t start, end;
    //start = clock();

    struct ThreadData *my_data;
    my_data = static_cast<ThreadData *>(threadarg);

    for( int x = my_data->index; x < my_data->index + my_data->count; x++ )
    {
        cout << "Thread: " << my_data->index << endl;
        clock_t start, end;
        start = clock();

        if (sigShareIn[x].Verify({theHash}, {pubs[x]}))
        {
            sigShareOutArr[x] = &sigShareIn[x];
            playersArr[x] = new size_t(x+1);
            counter.operator++();
        }
        end = clock();
        cout << end - start << ':' << CLOCKS_PER_SEC << ':' << (((float) end - start) / CLOCKS_PER_SEC)
             << endl;
    }

    //end = clock();
    //cout << end - start << ':' << CLOCKS_PER_SEC << ':' << (((float) end - start) / CLOCKS_PER_SEC)<< endl;

    pthread_exit(NULL);
}

//todo setup communication (star)
//todo try out different CPUS
int main()
{
    // To initialize a K of N threshold key under a
    // Joint-Feldman scheme:


    // 1. Each player calls Threshold::Create.
    // They send everyone commitment to the polynomial,
    // and send secret share fragments frags[j-1] to
    // the j-th player (All players have index >= 1).

    // PublicKey commits[N][K]
    // PrivateKey frags[N][N]
    std::vector <std::vector<PublicKey>> commits;
    std::vector <std::vector<PrivateKey>> frags;
    for (size_t i = 0; i < N; ++i)
    {
        commits.emplace_back(std::vector<PublicKey>());
        frags.emplace_back(std::vector<PrivateKey>());
        for (size_t j = 0; j < N; ++j)
        {
            if (j < K) {
                g1_t g;
                commits[i].emplace_back(PublicKey::FromG1(&g));
            }
            bn_t b;
            bn_new(b);
            frags[i].emplace_back(PrivateKey::FromBN(b));
        }
    }

    for (int i = 0; i < N; i++)
    {
        Threshold::Create(commits[i], frags[i], K, N);
    }

    for (int target = 1; target <= N; ++target)
    {
        for (int source = 1; source <= N; ++source)
        {
            Threshold::VerifySecretFragment(target, frags[source - 1][target - 1], commits[source - 1], K);
        }
    }

    std::vector <PublicKey> keys;
    keys.reserve(N);

    for (int i = 0; i < N; i++)
    {
        keys.push_back(commits[i][0]);
    }
    PublicKey masterPubkey = PublicKey::AggregateInsecure(keys);

    // recvdFrags[j][i] = frags[i][j]
    std::vector <std::vector<PrivateKey>> recvdFrags = {{}};
    for (int i = 0; i < N; ++i)
    {
        recvdFrags.emplace_back(std::vector<PrivateKey>());
        for (int j = 0; j < N; ++j)
        {
            recvdFrags[i].emplace_back(frags[j][i]);
        }
    }

    pubs.reserve(N);

    vector<PrivateKey> privs;
    privs.reserve(N);

    for( int x = 0; x < N; x++ )
    {
        PrivateKey priv = PrivateKey::AggregateInsecure(recvdFrags[x]);
        pubs.push_back(priv.GetPublicKey());
        privs.push_back(priv);
    }

    uint8_t msg[7] = {100, 100, 100, 100, 100, 100, 100};

    int messageSize = (size_t) sizeof(msg);

    Util::Hash256(theHash, msg, messageSize);

    sigShareIn.reserve(N);

    vector<InsecureSignature> sigShareOut;
    vector<size_t> players;
    sigShareOut.reserve(N);
    players.reserve(N);

    for( int x = 0; x < N; x++ )
    {
        sigShareIn.push_back(privs[x].SignInsecure(msg, messageSize));
    }

    clock_t start, end;
    start = clock();

    if (threaded)
    {
        pthread_t threads[Threads];
        vector<ThreadData> td;
        td.reserve(Threads);
        int each = N / Threads;
        cout << each << endl;
        for (int x = 0; x < Threads; x++)
        {
            cout << "main() : creating thread, " << x << endl;
            td[x] = ThreadData(x * each, each);

            int rc = pthread_create(&threads[x], NULL, executeSlave, (void *) &td[x]);

            if (rc)
            {
                cout << "Error:unable to create thread," << rc << endl;
                exit(-1);
            }
        }

        while (counter < N)
        {
            // Busy wait
            std::this_thread::sleep_for(10ms);
        }

        for( int x = 0; x < N; x++ )
        {
            if (sigShareOutArr[x] != nullptr)
            {
                sigShareOut.push_back(*sigShareOutArr[x]);
                players.push_back(*playersArr[x]);
            }
        }
    }
    else
    {
        for( int x = 0; x < N; x++ )
        {
            if (sigShareIn[x].Verify({theHash}, {pubs[x]}))
            {
                sigShareOut.push_back(sigShareIn[x]);
                players.push_back(x+1);
            }
        }
    }

    InsecureSignature signature = Threshold::AggregateUnitSigs(sigShareOut, msg, messageSize, &players[0], K);
    Util::Hash256(theHash, msg, sizeof(msg));

    if (!signature.Verify({theHash}, {masterPubkey}))
    {
        cout << "Verification failed" << endl;
    }

    end = clock();
    cout << end - start << ':' << CLOCKS_PER_SEC << ':' << (((float) end - start) / CLOCKS_PER_SEC)
         << endl;

    for (auto & x : playersArr)
    {
        delete x;
    }
}
