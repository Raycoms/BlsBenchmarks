#include <iostream>
#include <bls.hpp>
#include <random>

using namespace bls;
using namespace std;

void generateRandomArray(uint8_t *arr, const int size)
{
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_real_distribution<double> dist(1.0, 255.0);

    for(int i=0; i<size; i++)
    {
        arr[i] = dist(mt);
    }
}

int main()
{
    std::cout << "Hello, World!" << std::endl;

    const int seed = 30;

    vector<bls::PrivateKey> pks;
    vector<bls::PublicKey> pubks;

    pks.reserve(20);
    pubks.reserve(20);

    for (int i = 0; i < 20; i++)
    {
        auto *randSeed = new uint8_t[seed];
        generateRandomArray(randSeed, seed);
        pks.push_back(PrivateKey::FromSeed(randSeed, seed));
        delete[] randSeed;
        pubks.push_back(pks[i].GetPublicKey());
    }

    vector<bls::Signature> sigs;

    uint8_t msg[] = {100, 2, 254, 88, 90, 45, 23};
    sigs.reserve(20);

    for (int i = 0; i < 20; i++)
    {
        sigs.push_back(pks[i].Sign(msg, sizeof(msg)));
    }

    bls::Signature aggSig = bls::Signature::Aggregate(sigs);
    bls::PublicKey aggPubKey = bls::PublicKey::Aggregate(pubks);

    uint8_t sigBytes[bls::Signature::SIGNATURE_SIZE];
    aggSig.Serialize(sigBytes);

    bls::Signature aggSig2 = bls::Signature::FromBytes(sigBytes);
    aggSig2.SetAggregationInfo(bls::AggregationInfo::FromMsg(aggPubKey, msg, sizeof(msg)));

    cout << aggSig2.Verify() << endl;

    return 0;
}
