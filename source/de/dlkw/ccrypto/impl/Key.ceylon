import ceylon.whole {
    Whole,
    one,
    zero
}

import de.dlkw.ccrypto.api {
    RsaKey,
    RsaExponentPrivateKey,
    RsaCrtPrivateKey,
    RsaPublicKey
}

shared abstract class AbstractRsaKey(modulus)
        satisfies RsaKey
{
    shared actual Whole modulus;
    
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
    shared actual Integer bitLength = calcBitLength(modulus);
}

shared class RsaExponentPrivateKeyImpl(exponent, modulus)
        extends AbstractRsaKey(modulus)
        satisfies RsaExponentPrivateKey
{
    shared actual Whole exponent;
    Whole modulus;
}

shared class RsaCrtPrivateKeyImpl(p, q, dP, dQ, qInv)
        extends AbstractRsaKey(p * q)
        satisfies RsaCrtPrivateKey
{
    shared actual Whole p;
    shared actual Whole q;
    shared actual Whole dP;
    shared actual Whole dQ;
    shared actual Whole qInv;
}

shared class RsaPublicKeyImpl(exponent, modulus)
        extends AbstractRsaKey(modulus)
        satisfies RsaPublicKey
{
    shared actual Whole exponent;
    Whole modulus;
}
