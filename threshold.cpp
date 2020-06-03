#include <iostream>
#include <bls.hpp>
#include <random>
#include <pthread.h>

using namespace bls;
using namespace std;

int main()
{
    clock_t start, end;
    start = clock();

    std::cout << "Hello, World!" << std::endl;

    // To initialize a K of N threshold key under a
    // Joint-Feldman scheme:
    size_t K = 2;
    size_t N = 3;

    // 1. Each player calls Threshold::Create.
    // They send everyone commitment to the polynomial,
    // and send secret share fragments frags[j-1] to
    // the j-th player (All players have index >= 1).

    // PublicKey commits[N][K]
    // PrivateKey frags[N][N]
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

    PrivateKey sk1 = Threshold::Create(commits[0], frags[0], K, N);
    PrivateKey sk2 = Threshold::Create(commits[1], frags[1], K, N);
    PrivateKey sk3 = Threshold::Create(commits[2], frags[2], K, N);

    // 2. Each player calls Threshold::VerifySecretFragment
    // on all secret fragments they receive.  If any verify
    // false, they complain to abort the scheme.  (Note that
    // repeatedly aborting, or 'speaking' last, can bias the
    // master public key.)

    for (int target = 1; target <= N; ++target) {
        for (int source = 1; source <= N; ++source) {
            Threshold::VerifySecretFragment(
                    target, frags[source-1][target-1], commits[source-1], K);
        }
    }

    // 3. Each player computes the shared, master public key:
    // masterPubkey = PublicKey::AggregateInsecure(...)
    // They also create their secret share from all secret
    // fragments received (now verified):
    // secretShare = PrivateKey::AggregateInsecure(...)

    PublicKey masterPubkey = PublicKey::AggregateInsecure({
                                                                  commits[0][0], commits[1][0], commits[2][0]
                                                          });

    // recvdFrags[j][i] = frags[i][j]
    std::vector<std::vector<PrivateKey>> recvdFrags = {{}};
    for (int i = 0; i < N; ++i) {
        recvdFrags.emplace_back(std::vector<PrivateKey>());
        for (int j = 0; j < N; ++j) {
            recvdFrags[i].emplace_back(frags[j][i]);
        }
    }

    PrivateKey secretShare1 = PrivateKey::AggregateInsecure(recvdFrags[0]);
    PrivateKey secretShare2 = PrivateKey::AggregateInsecure(recvdFrags[1]);
    PrivateKey secretShare3 = PrivateKey::AggregateInsecure(recvdFrags[2]);

    uint8_t msg[] = {100, 2, 254, 88, 90, 45, 23};
    uint8_t hash[32];
    Util::Hash256(hash, msg, sizeof(msg));

    size_t players[] = {1, 3};

    // 4b. Alternatively, players may sign the message blindly, creating
    // a unit signature share: sigShare = secretShare.SignInsecure(...)
    // These signatures may be combined with lagrange coefficients to
    // sign the message: signature = Threshold::AggregateUnitSigs(...)
    // The advantage to this approach is that each player does not need
    // to know the final list of signatories.

    // For example, players 1 and 3 sign.
    InsecureSignature sigShareU1 = secretShare1.SignInsecure(
            msg, (size_t) sizeof(msg));
    InsecureSignature sigShareU3 = secretShare3.SignInsecure(
            msg, (size_t) sizeof(msg));
    InsecureSignature signature2 = Threshold::AggregateUnitSigs(
            {sigShareU1, sigShareU3}, msg, (size_t) sizeof(msg), players, K);

    cout << signature2.Verify({hash}, {masterPubkey}) << endl;

    end = clock();
    cout << end-start << ':' << CLOCKS_PER_SEC << ':' <<  (((float)end-start)/CLOCKS_PER_SEC) << endl;

    return 0;
}
