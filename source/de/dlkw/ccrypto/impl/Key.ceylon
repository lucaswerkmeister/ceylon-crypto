import ceylon.whole {
    Whole
}

import de.dlkw.ccrypto.api {
    RsaExponentPrivateKey,
    RsaCrtPrivateKey,
    RsaPublicKey
}
import de.dlkw.ccrypto.api.asn1 {
    asn1Integer,
    Asn1Integer,
    Asn1Sequence,
    Asn1Whole,
    Asn1EncodingError=EncodingError,
    IdentityInfo,
    encodeAsn1Sequence,
    asn1Whole,
    UniversalTag,
    Option,
    Tag,
    Decoder,
    DecodingError,
    SequenceDecoder,
    Descriptor,
    Asn1IntegerDecoder,
    Asn1WholeDecoder
}

shared class RsaPublicKeyImpl(exponent, modulus)
        satisfies RsaPublicKey
{
    shared actual Whole modulus;
    shared actual Whole exponent;
    shared actual Integer bitLength = calcBitLength(modulus);
}

shared class RsaExponentPrivateKeyImpl(exponent, modulus)
        satisfies RsaExponentPrivateKey
{
    shared actual Whole modulus;
    shared actual Whole exponent;
    shared actual Integer bitLength = calcBitLength(modulus);
}

shared class RsaCrtPrivateKeyImpl(p, q, dP, dQ, qInv)
        satisfies RsaCrtPrivateKey
{
    shared actual Whole p;
    shared actual Whole q;
    shared actual Whole dP;
    shared actual Whole dQ;
    shared actual Whole qInv;

    shared actual Whole modulus = p * q;
    shared actual Integer bitLength = calcBitLength(modulus);
}

shared class Asn1RsaPrivateKeyImpl(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer, valu)
        extends Asn1Sequence<[Asn1Integer, Asn1Whole, Asn1Whole, Asn1Whole, Asn1Whole, Asn1Whole, Asn1Whole, Asn1Whole, Asn1Whole]>.internal(
    encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer, valu)
        satisfies RsaExponentPrivateKey & RsaCrtPrivateKey
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentOctetsOffset;
    Boolean violatesDer;
    [Asn1Integer, Asn1Whole, Asn1Whole, Asn1Whole, Asn1Whole, Asn1Whole, Asn1Whole, Asn1Whole, Asn1Whole] valu;

    shared actual Whole modulus => valu[1].val;
    shared actual Integer bitLength = calcBitLength(modulus);
    
    shared Whole publicExponent => valu[2].val;
    shared actual Whole exponent => valu[3].val;

    shared actual Whole p => valu[4].val;
    shared actual Whole q => valu[5].val;
    shared actual Whole dP => valu[6].val;
    shared actual Whole dQ => valu[7].val;
    shared actual Whole qInv => valu[8].val;
}

shared Asn1RsaPrivateKeyImpl rsaCrtPrivateKeyImpl(publicExponent, privateExponent, p, q, dP, dQ, qInv, Tag tag = UniversalTag.sequence)
{
    Whole publicExponent;
    Whole privateExponent;
    Whole p;
    Whole q;
    Whole dP;
    Whole dQ;
    Whole qInv;
    
    Whole modulus = p * q;
    
    Asn1Integer aVersion = asn1Integer(0);
    Asn1Whole aModulus = asn1Whole(modulus);
    Asn1Whole aPublicExponent = asn1Whole(publicExponent);
    Asn1Whole aPrivateExponent = asn1Whole(privateExponent);
    Asn1Whole aQ = asn1Whole(q);
    Asn1Whole aP = asn1Whole(p);
    Asn1Whole aDP = asn1Whole(dP);
    Asn1Whole aDQ = asn1Whole(dQ);
    Asn1Whole aQInv = asn1Whole(qInv);

    value seqValue = [
        aVersion,
        aModulus,
        aPublicExponent,
        aPrivateExponent,
        aP,
        aQ,
        aDP,
        aDQ,
        aQInv];
    value seqEncodingResult = encodeAsn1Sequence(seqValue,
        [Option.mandatory, Option.mandatory, Option.mandatory, Option.mandatory, Option.mandatory, Option.mandatory, Option.mandatory, Option.mandatory, Option.mandatory
        ], tag);
    assert (!is Asn1EncodingError seqEncodingResult);
    
    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = seqEncodingResult;
    return Asn1RsaPrivateKeyImpl(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false,
         [aVersion, aModulus, aPublicExponent, aPrivateExponent, aP, aQ, aDP, aDQ, aQInv]);
}

shared class Asn1RsaPrivateKeyDecoder(Tag tag = UniversalTag.sequence)
        extends Decoder<Asn1RsaPrivateKeyImpl>(tag)
{
    value delegate = SequenceDecoder<[Asn1Integer, Asn1Whole, Asn1Whole, Asn1Whole, Asn1Whole, Asn1Whole, Asn1Whole, Asn1Whole, Asn1Whole]>([
        Descriptor((_)=>Asn1IntegerDecoder()),
        Descriptor((_)=>Asn1WholeDecoder()),
        Descriptor((_)=>Asn1WholeDecoder()),
        Descriptor((_)=>Asn1WholeDecoder()),
        Descriptor((_)=>Asn1WholeDecoder()),
        Descriptor((_)=>Asn1WholeDecoder()),
        Descriptor((_)=>Asn1WholeDecoder()),
        Descriptor((_)=>Asn1WholeDecoder()),
        Descriptor((_)=>Asn1WholeDecoder())
    ]);
    
    shared actual [Asn1RsaPrivateKeyImpl, Integer]|DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, Boolean violatesDer)
    {
        value decodingResult = delegate.decodeGivenTagAndLength(input, offset, identityInfo, length, identityOctetsOffset, lengthOctetsOffset, violatesDer);
        if (is DecodingError decodingResult) {
            return decodingResult;
        }
        value [seq, nextPos] = decodingResult;
        if (seq.val[0].val != 0) {
            return DecodingError(offset, "ASN.1 decoding of RSA private key with more than 2 primes not supported.");
        }
        value result = Asn1RsaPrivateKeyImpl(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset - identityOctetsOffset, offset - identityOctetsOffset, violatesDer, seq.val);
        return [result, nextPos];
    }
}
