import ceylon.whole {
    Whole,
    zero,
    wholeNumber
}
import ceylon.collection {
    HashMap
}

shared interface AsymmetricEncryption
{
    shared formal Integer maxPlaintextLength;
    shared formal Byte[] encrypt(Byte[] plaintext);
    shared formal Byte[] decrypt(Byte[] ciphertext);
}

shared interface Padding
{
    shared formal Byte[] pad(Byte[] input);
}

/*
class RSA()
{
    shared Whole encrypt(Whole plaintext, Whole e, Whole n) => plaintext.moduloPower(exponent, modulus);
    shared Whole decrypt(Whole ciphertext) => ciphertext.moduloPower(exponent, modulus);
}
 */

/*
shared interface PrivateKey{}
shared interface Signature
{
    shared formal String algorithmName;
    shared formal void init(PrivateKey privateKey);
    shared formal void update(Byte[] input);
    shared formal Byte[] sign();
    shared formal Byte[] updateAndSign(Byte[] input);
}

class DigestingSignature(algorithmName, digest, padding, encryption)
        satisfies Signature
{
    shared actual String algorithmName;
    
    Digest digest;
    Padding padding;
    AsymmetricEncryption encryption;
    
    shared actual void update(Byte[] input) => digest.update(input);
    shared actual void updateAndSign(Byte[] input) => sign(digest.updateAndDigest(input));
    
    shared actual Byte[] sign() => encryption.encrypt(padding.pad(digest.digest()));
}

shared object sha256WithRsa
        extends DigestingSignature("SHA256withRSA", sha256)
{
}
*/

shared Whole os2ip(Byte[] msg)
{
    variable Whole num = zero;
    for (b in msg) {
        num = num.leftLogicalShift(8).or(wholeNumber(b.unsigned));
    }
    return num;
}

shared Byte[] i2osp(msg, Integer emLen)
{
    variable Whole msg;
    
    variable Byte[] output = [];
    for (i in 0:emLen) {
        value b =  msg.integer.and(#ff).byte;
        output = output.withLeading(b);
        msg = msg.rightArithmeticShift(8);
    }
    return output;
}

shared Whole rsaenc(Whole input, Whole exp, Whole mod) => input.moduloPower(exp, mod);