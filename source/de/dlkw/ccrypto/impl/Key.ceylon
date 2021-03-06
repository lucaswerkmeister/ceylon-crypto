import ceylon.whole {
    Whole
}

import de.dlkw.ccrypto.api {
    RsaExponentPrivateKey,
    RsaCrtPrivateKey,
    RsaPublicKey,
    PublicKey
}
import de.dlkw.asn1 {
    asn1Integer,
    Asn1Integer,
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
    Asn1WholeDecoder,
    Asn1Sequence,
    Asn1Value
}
import de.dlkw.ccrypto.api.asn1.x509 {
    SubjectPublicKeyInfo
}
import de.dlkw.ccrypto.api.asn1.pkcs {
    rsaEncryptionAlgId
}

shared class RsaPublicKeyImpl(exponent, modulus)
        satisfies RsaPublicKey
{
    shared actual Whole modulus;
    shared actual Whole exponent;
    shared actual Integer bitLength = calcBitLength(modulus);
}

shared class Asn1RsaPublicKeyImpl(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, valu)
        extends Asn1Sequence<[Asn1Whole, Asn1Whole]>(
    encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, valu)
        satisfies RsaPublicKey
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    [Asn1Whole, Asn1Whole] valu;
    
    shared actual Whole modulus => valu[0].val;
    shared actual Whole exponent => valu[1].val;
    shared actual Integer bitLength = calcBitLength(modulus);
}

shared class Asn1RsaPublicKeyImplDecoder(Tag tag = UniversalTag.sequence)
         extends Decoder<Asn1RsaPublicKeyImpl>(tag)
{
    value delegate = SequenceDecoder<[Asn1Whole, Asn1Whole]>
            ([Descriptor((_)=>Asn1WholeDecoder()), Descriptor((_)=>Asn1WholeDecoder())]);
    
    shared actual [Asn1RsaPublicKeyImpl, Integer]|DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        value x = delegate.decodeGivenTagAndLength(input, offset, identityInfo, length, identityOctetsOffset, lengthOctetsOffset, violatesDer);
        if (is DecodingError x) {
            return x;
        }
        value [seq, nextPos] = x;
        violatesDer ||= seq.violatesDer;
        
        value decoded = seq.val;
        value r = Asn1RsaPublicKeyImpl(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset, offset, violatesDer, decoded);
        return [r, nextPos];
    }
}

shared Asn1RsaPublicKeyImpl rsaPublicKey(exponent, modulus, Tag tag = UniversalTag.sequence)
{
    Whole modulus;
    Whole exponent;
    
    value aModulus = asn1Whole(modulus);
    value aExponent = asn1Whole(exponent);
    
    value enc = encodeAsn1Sequence([aModulus, aExponent], [Option.mandatory, Option.mandatory], tag);
    assert (!is Asn1EncodingError enc);
    
    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = enc;
    return Asn1RsaPublicKeyImpl(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false, [aModulus, aExponent]);
}

shared <PublicKey & Asn1Value<Anything>> | DecodingError publicKeyFrom(SubjectPublicKeyInfo<> subjectPublicKeyInfo)
{
    if (subjectPublicKeyInfo.algorithmIdentifier == rsaEncryptionAlgId) {
        if (subjectPublicKeyInfo.encodedKey.unusedBits != 0) {
            return DecodingError(-1, "BIT STRING length of public key encoding not multiple of 8");
        }
        return rsaPublicKeyFrom(subjectPublicKeyInfo.encodedKey.bytes);
    }
    return DecodingError(-1, "cannot decoded public key for unknown algorithm identifier");
}

shared Asn1RsaPublicKeyImpl | DecodingError rsaPublicKeyFrom(Byte[] encoded)
{
    value decoded = Asn1RsaPublicKeyImplDecoder().decode(encoded);
    if (is DecodingError decoded) {
        return decoded;
    }
    return decoded[0];
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
        extends Asn1Sequence<[Asn1Integer, Asn1Whole, Asn1Whole, Asn1Whole, Asn1Whole, Asn1Whole, Asn1Whole, Asn1Whole, Asn1Whole]>(
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
