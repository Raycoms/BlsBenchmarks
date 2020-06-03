#include <iostream>
#include <bls.hpp>
#include <random>
#include <pthread.h>
#include <thread>
#include <atomic>
#include <mutex>

using namespace bls;
using namespace std;

const size_t K = 70;
const size_t N = 100;

atomic_int counter(0);
vector<PublicKey> pubs;

vector<InsecureSignature> sigShareIn;

vector<size_t> players;
vector<InsecureSignature> sigShareOut;
mutex values_mutex;



void values_push_back(const InsecureSignature& sig, const int player)
{
    values_mutex.lock();
    sigShareOut.push_back(sig);
    players.push_back(player);
    values_mutex.unlock();
}

struct ThreadData
{
    int index;
    int count;

    ThreadData(const int index, const int count): index(index), count(count){};
};

void *executeSlave(void *threadarg)
{

    for( int x = 0; x < N; x++ )
    {
        sigShareU1[x].Verify({hash}, {pubs[x]});
        players.push_back(x+1);
    }
}

//todo parallelize verification
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
    uint8_t hash[32];
    int messageSize = (size_t) sizeof(msg);

    Util::Hash256(hash, msg, messageSize);

    sigShareIn.reserve(N);
    sigShareOut.reserve(N);
    players.reserve(N);

    for( int x = 0; x < N; x++ )
    {
        sigShareIn.push_back(privs[x].SignInsecure(msg, messageSize));
    }

    clock_t start, end;
    start = clock();


    //
    pthread_t threads[N];
    vector<ThreadData> td;
    td.reserve(N);

    for( int x = 0; x < N; x++ )
    {
        cout << "main() : creating thread, " << x << endl;
        PrivateKey priv = PrivateKey::AggregateInsecure(recvdFrags[x]);
        pubs.push_back(priv.GetPublicKey());
        td[x] = ThreadData(x+1, &priv, &masterPubkey);

        int rc = pthread_create(&threads[x], NULL, executeSlave, (void *)&td[x]);

        if (rc) {
            cout << "Error:unable to create thread," << rc << endl;
            exit(-1);
        }
    }


    //todo while atomic int < what we want, wait >

    for( int x = 0; x < N; x++ )
    {
        sigShareU1[x].Verify({hash}, {pubs[x]});
        players.push_back(x+1);
    }

    InsecureSignature signature = Threshold::AggregateUnitSigs(sigShareOut, msg, messageSize, &players[0], K);
    Util::Hash256(hash, msg, sizeof(msg));

    if (!signature.Verify({hash}, {masterPubkey}))
    {
        cout << "Verification failed" << endl;
    }

    end = clock();
    cout << end - start << ':' << CLOCKS_PER_SEC << ':' << (((float) end - start) / CLOCKS_PER_SEC)
         << endl;
}
