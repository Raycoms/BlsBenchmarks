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
const size_t Threads = 5;

atomic_int counter(0);
vector<PublicKey> pubs;

vector<InsecureSignature> sigShareIn;

uint8_t theHash[32];

size_t *playersArr[N];
InsecureSignature *sigShareOutArr[N];

struct ThreadData {
    int index;
    int count;

    ThreadData(const int index, const int count) : index(index), count(count) {};
};

void executeSlave(ThreadData my_data) {
    auto start = std::chrono::steady_clock::now();

    for (int x = my_data.index; x < my_data.index + my_data.count; x++) {
        if (sigShareIn[x].Verify({theHash}, {pubs[x]})) {
            sigShareOutArr[x] = &sigShareIn[x];
            playersArr[x] = new size_t(x + 1);
            counter.operator++();
        }
    }

    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed_seconds = end - start;
    cout << "Time: " << elapsed_seconds.count() << endl;

    pthread_exit(NULL);
}

//todo setup communication (star)
//todo try out different CPUS
int main() {

    std::vector<std::vector<PublicKey>> commits;
    std::vector<std::vector<PrivateKey>> frags;
    for (size_t i = 0; i < N; ++i) {
        commits.emplace_back(std::vector<PublicKey>());
        frags.emplace_back(std::vector<PrivateKey>());
        for (size_t j = 0; j < N; ++j) {
            if (j < K) {
                g1_t g;
                commits[i].emplace_back(PublicKey::FromG1(&g));
            }
            bn_t b;
            bn_new(b);
            frags[i].emplace_back(PrivateKey::FromBN(b));
        }
    }

    for (int i = 0; i < N; i++) {
        Threshold::Create(commits[i], frags[i], K, N);
    }

    for (int target = 1; target <= N; ++target) {
        for (int source = 1; source <= N; ++source) {
            Threshold::VerifySecretFragment(target, frags[source - 1][target - 1], commits[source - 1], K);
        }
    }

    std::vector<PublicKey> keys;
    keys.reserve(N);

    for (int i = 0; i < N; i++) {
        keys.push_back(commits[i][0]);
    }
    PublicKey masterPubkey = PublicKey::AggregateInsecure(keys);

    // recvdFrags[j][i] = frags[i][j]
    std::vector<std::vector<PrivateKey>> recvdFrags = {{}};
    for (int i = 0; i < N; ++i) {
        recvdFrags.emplace_back(std::vector<PrivateKey>());
        for (int j = 0; j < N; ++j) {
            recvdFrags[i].emplace_back(frags[j][i]);
        }
    }

    pubs.reserve(N);

    vector<PrivateKey> privs;
    privs.reserve(N);

    for (int x = 0; x < N; x++) {
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

    for (int x = 0; x < N; x++) {
        sigShareIn.push_back(privs[x].SignInsecure(msg, messageSize));
    }

    auto start = std::chrono::steady_clock::now();

    int each = N / Threads;
    cout << each << endl;
    for (int x = 0; x < Threads; x++) {
        cout << "main() : creating thread, " << x << endl;
        std::thread th(executeSlave, ThreadData(x * each, each));
        th.detach();
    }

    while (counter < N) {
        // Busy wait
        std::this_thread::sleep_for(10ms);
    }

    for (int x = 0; x < N; x++) {
        if (sigShareOutArr[x] != nullptr) {
            sigShareOut.push_back(*sigShareOutArr[x]);
            players.push_back(*playersArr[x]);
        }
    }

    InsecureSignature signature = Threshold::AggregateUnitSigs(sigShareOut, msg, messageSize, &players[0], K);
    Util::Hash256(theHash, msg, sizeof(msg));

    if (!signature.Verify({theHash}, {masterPubkey})) {
        cout << "Verification failed" << endl;
    }

    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed_seconds = end - start;

    cout << "Final:" << endl;
    cout << elapsed_seconds.count() << endl;

    for (auto &x : playersArr) {
        delete x;
    }
}
