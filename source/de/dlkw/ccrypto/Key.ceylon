import ceylon.whole {
    Whole,
    one,
    zero
}

shared abstract class RsaKey(modulus)
{
    shared Whole modulus;
    
    shared Integer calcBitLength(Whole number)
    {
        if (number == zero) {
            return 0;
        }
        variable Integer len = 0;
        variable Whole n = one;
        while (n <= number) {
            len += 1;
            n = n.leftLogicalShift(1);
        }
        return len;
    }
    shared Integer bitLength = calcBitLength(modulus);
    shared Integer octetLength => (bitLength - 1) / 8 + 1;
}

shared abstract class RsaPrivateKey(modulus)
        of RsaExponentPrivateKey | RsaCrtPrivateKey
        extends RsaKey(modulus)
{
    Whole modulus;
}

shared class RsaExponentPrivateKey(exponent, modulus)
        extends RsaPrivateKey(modulus)
{
    shared Whole exponent;
    Whole modulus;
}

shared class RsaCrtPrivateKey(p, q, dP, dQ, qInv)
        extends RsaPrivateKey(p * q)
{
    shared Whole p;
    shared Whole q;
    shared Whole dP;
    shared Whole dQ;
    shared Whole qInv;
}

shared class RsaPublicKey(exponent, modulus)
        extends RsaKey(modulus)
{
    shared Whole exponent;
    Whole modulus;
}