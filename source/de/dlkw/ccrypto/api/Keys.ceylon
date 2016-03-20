import ceylon.whole {
    Whole
}

shared interface PrivateKey{}
shared interface PublicKey{}

shared class KeyPair<Private, Public>(privateKey, publicKey)
        given Private satisfies PrivateKey
{
    shared Private privateKey;
    shared Public publicKey;
}

shared interface RsaKey
{
    shared formal Whole modulus;
    
    shared formal Integer bitLength;
    shared Integer octetLength => (bitLength - 1) / 8 + 1;
}

shared interface RsaPrivateKey
        of RsaExponentPrivateKey | RsaCrtPrivateKey
        satisfies PrivateKey & RsaKey
{}

shared interface RsaExponentPrivateKey
        satisfies RsaPrivateKey
{
    shared formal Whole exponent;
}

shared interface RsaCrtPrivateKey
        satisfies RsaPrivateKey
{
    shared formal Whole p;
    shared formal Whole q;
    shared formal Whole dP;
    shared formal Whole dQ;
    shared formal Whole qInv;
}

shared interface RsaPublicKey
        satisfies PublicKey & RsaKey
{
    shared formal Whole exponent;
}
