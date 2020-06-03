#include <iostream>
#include <bls.hpp>
#include <random>
#include <pthread.h>
#include <thread>
#include <shared_mutex>

using namespace bls;
using namespace std;

struct Tuple
{
    int id;
    InsecureSignature sig;

    Tuple(const int id, const InsecureSignature &sig): id(id), sig(sig){};
};

struct GlobalData
{
    std::vector<uint8_t*> messages;
    std::shared_timed_mutex messagesLock;

    std::vector<std::vector<Tuple>> partialSignatures;
    std::shared_timed_mutex partialSignaturesLock;

    std::vector<InsecureSignature> thresholdSignatures;
    std::shared_timed_mutex thresholdSignaturesLock;
};

GlobalData data;

struct ThreadData
{
    int thread_id;
    PrivateKey keyShare;
    PublicKey masterPub;

    ThreadData(const int id, const PrivateKey *keyShare, const PublicKey *publicKey): thread_id(id), keyShare(*keyShare), masterPub(*publicKey){};
};


void *executeSlave(void *threadarg)
{
    struct ThreadData *my_data;
    my_data = static_cast<ThreadData *>(threadarg);

    int id = my_data->thread_id;
    PrivateKey keyShare = my_data->keyShare;
    PublicKey masterPub = my_data->masterPub;

    uint8_t currentMessage[100][7];
    uint8_t hash[100][32];

    cout << "Thread ID : " <<  id << endl;

    // i that indicates the round
    // state that indicates if it waiting for a new message, or if it is waiting for the signature.
    int i = 0;
    int state = 0;

    while (i < 100)
    {
        if (state == 0)
        {
            while (!data.messagesLock.try_lock_shared())
            {
                std::this_thread::sleep_for(1ms);
            }


            if (data.messages.size() > i)
            {
                for (int x = 0; x < sizeof(currentMessage[i]); x++)
                {
                    currentMessage[i][x] = data.messages[i][x];
                }

                data.messagesLock.unlock_shared();

                Util::Hash256(hash[i], currentMessage[i], sizeof(currentMessage[i]));
                InsecureSignature sigShareU1 = keyShare.SignInsecure(currentMessage[i], (size_t) sizeof(currentMessage[i]));
                //cout << hash << endl;
                //cout << currentMessage << endl;

                if (id == 1)
                {
                    currentMessage[i][0] = 0;
                    Util::Hash256(hash[i], currentMessage[i], sizeof(currentMessage[i]));
                    sigShareU1 = keyShare.SignInsecure(currentMessage[i], (size_t) sizeof(currentMessage[i]));
                }

                while (!data.partialSignaturesLock.try_lock())
                {
                    std::this_thread::sleep_for(1ms);
                }

                data.partialSignatures[i].push_back(Tuple(id, sigShareU1));
                data.partialSignaturesLock.unlock();
                state = 1;
            }
            else
            {
                data.messagesLock.unlock_shared();
            }
        }
        else
        {
            while (!data.thresholdSignaturesLock.try_lock_shared())
            {
                std::this_thread::sleep_for(1ms);
            }

            if (data.thresholdSignatures.size() > i)
            {

                InsecureSignature signature = data.thresholdSignatures[i];
                data.thresholdSignaturesLock.unlock_shared();

                if (!signature.Verify({hash[i]}, {masterPub}))
                {
                    cout << "Didn't work for me: " << id << endl;
                }
                i++;
                state = 0;
            }
            else
            {
                data.thresholdSignaturesLock.unlock_shared();
            }
        }

        std::this_thread::sleep_for(1ms);
    }

    pthread_exit(NULL);
}

int main()
{
    // To initialize a K of N threshold key under a
    // Joint-Feldman scheme:
    size_t K = 50;
    size_t N = 60;

    // 1. Each player calls Threshold::Create.
    // They send everyone commitment to the polynomial,
    // and send secret share fragments frags[j-1] to
    // the j-th player (All players have index >= 1).

    // PublicKey commits[N][K]
    // PrivateKey frags[N][N]
    std::vector<std::vector<PublicKey>> commits;
    std::vector<std::vector<PrivateKey>> frags;
    for (size_t i = 0; i < N; ++i)
    {
        commits.emplace_back(std::vector<PublicKey>());
        frags.emplace_back(std::vector<PrivateKey>());
        for (size_t j = 0; j < N; ++j)
        {
            if (j < K)
            {
                g1_t g;
                commits[i].emplace_back(PublicKey::FromG1(&g));
            }
            bn_t b;
            bn_new(b);
            frags[i].emplace_back(PrivateKey::FromBN(b));
        }
    }

    for (int i = 0; i < N; i ++)
    {
        Threshold::Create(commits[i], frags[i], K, N);
    }

    for (int target = 1; target <= N; ++target)
    {
        for (int source = 1; source <= N; ++source)
        {
            Threshold::VerifySecretFragment(target, frags[source-1][target-1], commits[source-1], K);
        }
    }

    std::vector<PublicKey> keys;
    keys.reserve(N);

    for (int i = 0; i < N; i++)
    {
        keys.push_back(commits[i][0]);
    }
    PublicKey masterPubkey = PublicKey::AggregateInsecure(keys);

    // recvdFrags[j][i] = frags[i][j]
    std::vector<std::vector<PrivateKey>> recvdFrags = {{}};
    for (int i = 0; i < N; ++i)
    {
        recvdFrags.emplace_back(std::vector<PrivateKey>());
        for (int j = 0; j < N; ++j)
        {
            recvdFrags[i].emplace_back(frags[j][i]);
        }
    }

    data.messages.reserve(100);
    data.thresholdSignatures.reserve(100);
    data.partialSignatures.reserve(100);

    for (int x = 0; x < 100; x++)
    {
        vector<Tuple> vet;
        vet.reserve(N);
        data.partialSignatures[x] = vet;
    }

    pthread_t threads[N];
    vector<ThreadData> td;
    td.reserve(N);

    vector<PublicKey> pubs;
    pubs.reserve(N);

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

    int i = 0;
    int state = 0;
    uint8_t msg[100][7];
    uint8_t hash[100][32];

    while (i < 100)
    {
        if (state == 0)
        {
            std::random_device rd;
            std::mt19937 mt(rd());
            std::uniform_real_distribution<double> dist(1.0, 255.0);

            for(unsigned char &x : msg[i])
            {
                x = dist(mt);
            }

            Util::Hash256(hash[i], msg[i], sizeof(msg[i]));

            while (!data.messagesLock.try_lock())
            {
                std::this_thread::sleep_for(1ms);
            }

            data.messages.push_back(msg[i]);
            data.messagesLock.unlock();
            state = 1;
        }
        else
        {
            while (!data.partialSignaturesLock.try_lock())
            {
                std::this_thread::sleep_for(1ms);
            }

            if (data.partialSignatures[i].size() >= K)
            {
                clock_t start, end;
                start = clock();

                const int size =  data.partialSignatures[i].size();
                cout << "Create Threshold Sig: " << size << endl;

                vector<size_t> players;
                vector<InsecureSignature> validSignatures;
                validSignatures.reserve(size);

                for (int x = 0; x < size; x++)
                {
                    Tuple tuple = data.partialSignatures[i][x];
                    if (tuple.sig.Verify({hash[i]}, {pubs[tuple.id-1]}))
                    {
                        players.push_back(tuple.id);
                        validSignatures.push_back(tuple.sig);
                    }
                    else
                    {
                        cout << "Invalid signature" << endl;
                    }
                }

                data.partialSignaturesLock.unlock_shared();

                if (validSignatures.size() >= K)
                {
                    int messageSize = (size_t) sizeof(msg[i]);

                    InsecureSignature signature = Threshold::AggregateUnitSigs(validSignatures, msg[i], messageSize,&players[0], K);
                    Util::Hash256(hash[i], msg[i], sizeof(msg[i]));

                    if (!signature.Verify({hash[i]}, {masterPubkey}))
                    {
                        cout << "Verification failed" << endl;
                        throw "BHAL";
                    }

                    end = clock();
                    cout << end - start << ':' << CLOCKS_PER_SEC << ':' << (((float) end - start) / CLOCKS_PER_SEC)
                         << endl;

                    while (!data.thresholdSignaturesLock.try_lock())
                    {
                        std::this_thread::sleep_for(1ms);
                    }

                    data.thresholdSignatures.push_back(signature);
                    data.thresholdSignaturesLock.unlock();

                    state = 0;
                    i++;
                }
            }
            else
            {
                data.partialSignaturesLock.unlock();
            }
        }
        std::this_thread::sleep_for(1ms);
    }

    return 0;
}
