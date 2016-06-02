import ceylon.time {
    Instant
}
import ceylon.time.iso8601 {
    parseZoneDateTime
}

import de.dlkw.ccrypto.api.asn1.pkcs {
    AlgorithmIdentifier,
    sha256WithRsaSsaPssAndMgf1Sha256
}
import de.dlkw.ccrypto.asn1 {
    IdentityInfo,
    BitString,
    TaggedValue,
    Asn1Integer,
    GeneralizedTime,
    UTCTime,
    ObjectIdentifier,
    Asn1Value,
    Asn1Sequ,
    Asn1SequenceOf,
    Asn1SetOf,
    OctetString,
    Asn1Boolean,
    UniversalTag,
    encodeAsn1Sequence,
    Tag,
    Option,
    EncodingError,
    bitStringFromBytes,
    generalizedTime,
    taggedValue,
    asn1Integer
}

shared class Certificate(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Sequ<[TBSCertificate, AlgorithmIdentifier<>, BitString]>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    [TBSCertificate, AlgorithmIdentifier<>, BitString] elements;
}

shared Certificate certificate(tbsCertificate, algorithmIdentifier, signatureValue, Tag tag = UniversalTag.sequence)
{
    TBSCertificate tbsCertificate;
    AlgorithmIdentifier<> algorithmIdentifier;
    Byte[] signatureValue;
    
    value bitString = bitStringFromBytes(signatureValue);
    assert (!is EncodingError bitString);
    value enc = encodeAsn1Sequence([tbsCertificate, algorithmIdentifier, bitString], [Option.mandatory, Option.mandatory, Option.mandatory], tag);
    assert (!is EncodingError enc);
    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = enc;
    return Certificate(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false,
        [tbsCertificate, algorithmIdentifier, bitString]);
}

shared class TBSCertificate(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Sequ<[TaggedValue<Asn1Integer>, Asn1Integer, AlgorithmIdentifier<>, RDNSequence, Validity, RDNSequence, SubjectPublicKeyInfo<Asn1Value<Anything>>, BitString?, BitString?, TaggedValue<Extensions>?]>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    [TaggedValue<Asn1Integer>, Asn1Integer, AlgorithmIdentifier<>, RDNSequence, Validity, RDNSequence, SubjectPublicKeyInfo<Asn1Value<Anything>>, BitString?, BitString?, TaggedValue<Extensions>?] elements;
}

shared TBSCertificate | EncodingError tbsCertificate(version, serialNumber, signature, issuer, validity,
     subject, subjectPublicKeyInfo, extensions)
{
    Integer version;
    if (!(1 <= version <= 3)) {
        return EncodingError("version out of range");
    }
    
    Integer serialNumber;
    AlgorithmIdentifier<> signature;
    
    RDNSequence issuer;
    Validity validity;
    if (!validity.notBefore.smallerThan(validity.notAfter)) {
        return EncodingError("notBefore must lie before notAfter");
    }
    
    RDNSequence subject;
    SubjectPublicKeyInfo<> subjectPublicKeyInfo;
    Extensions? extensions;
    
    value asn1Version = taggedValue(asn1Integer(version), Tag(0));
    value asn1Serial = asn1Integer(serialNumber);
    value asn1Extensions = if (exists extensions)
        then taggedValue(extensions, Tag(3))
        else null;
    
    value enc = encodeAsn1Sequence([asn1Version, asn1Serial, signature, issuer, validity, subject,
            subjectPublicKeyInfo, null, null, asn1Extensions],
            [asn1Integer(1), Option.mandatory, Option.mandatory, Option.mandatory, Option.mandatory, Option.mandatory,
            Option.mandatory, Option.optional, Option.optional, Option.optional],
            UniversalTag.sequence);
    assert (!is EncodingError enc);
    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = enc;
    return TBSCertificate(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false,
        [asn1Version, asn1Serial, signature, issuer, validity, subject, subjectPublicKeyInfo, null, null, asn1Extensions]);
}

/*
class TBSCertificateBuilder()
{
    variable Integer _version = 3;
    variable Integer? _serialNumber = null;
    variable AlgorithmIdentifier<>? _signature = null;
    variable RDNSequence _issuer
    
    shared TBSCertificateBuilder version(Integer _version)
    {
        this._version = _version;
        return this;
    }

    shared TBSCertificateBuilder serialNumber(Integer _serialNumber)
    {
        this._serialNumber = _serialNumber;
        return this;
    }
    
    shared TBSCertificateBuilder signature(AlgorithmIdentifier<> _signature)
    {
        this._signature = _signature;
        return this;
    }
    
    TBSCertificate | EncodingError build()
    {
        value serial = _serialNumber;
        if (is Null serial) {
            return EncodingError("must specify serial number");
        }
        
        value sig = _signature;
        if (is Null sig) {
            return EncodingError("must specify signature algorithm identifier");
        }

        return tbsCertificate(_version, serial, sig, );
    }
}
 */

shared class RDNSequence(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1SequenceOf<RelativeDistinguishedName>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    RelativeDistinguishedName[] elements;
}

shared RDNSequence rdnSequence(Tag tag = UniversalTag.sequence, RelativeDistinguishedName* rdns)
{
    value enc = encodeAsn1Sequence(rdns, rdns.collect((_)=>Option.mandatory), tag);
    assert (!is EncodingError enc);
    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = enc;
    return RDNSequence(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false, rdns);
}

shared class RelativeDistinguishedName(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1SetOf<AttributeValueAssertion<>>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    AttributeValueAssertion<>[] elements;
}

shared RelativeDistinguishedName relativeDistinguishedName(Tag tag = UniversalTag.set, AttributeValueAssertion<>* avas)
{
    value enc = encodeAsn1Sequence(avas, avas.collect((_)=>Option.mandatory), tag);
    assert (!is EncodingError enc);
    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = enc;
    return RelativeDistinguishedName(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false, avas);
}

shared class AttributeValueAssertion<out Parameters = Asn1Value<Anything>>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Sequ<[ObjectIdentifier, Parameters?]>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        given Parameters satisfies Asn1Value<Anything>
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    [ObjectIdentifier, Parameters] elements;
}

shared AttributeValueAssertion<P> attributeValueAssertion<P>(ObjectIdentifier oid, P parameters, Tag tag = UniversalTag.sequence)
        given P satisfies Asn1Value<Anything>
{
    value enc = encodeAsn1Sequence([oid, parameters], [Option.mandatory, Option.mandatory], tag);
    assert (!is EncodingError enc);
    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = enc;
    return AttributeValueAssertion(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false, [oid, parameters]);
}

shared class Validity(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Sequ<Time[2]>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    Time[2] elements;
    
    shared Instant notBefore
    {
        value val = elements[0];
        if (is GeneralizedTime val) {
            return val.val;
        }
        else {
            throw AssertionError("unimplemented");
        }
    }
    
    shared Instant notAfter
    {
        value val = elements[1];
        if (is GeneralizedTime val) {
            return val.val;
        }
        else {
            throw AssertionError("unimplemented");
        }
    }
}

shared alias Time => UTCTime | GeneralizedTime;

shared Validity validity(Instant notBefore, Instant notAfter, Tag tag = UniversalTag.sequence)
{
    value gtNotBefore = generalizedTime(notBefore);
    assert (!is EncodingError gtNotBefore);
    value gtNotAfter = generalizedTime(notAfter);
    assert (!is EncodingError gtNotAfter);

    value x = encodeAsn1Sequence([gtNotBefore, gtNotAfter], [Option.mandatory, Option.mandatory], tag);
    assert (!is EncodingError x);
    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = x;
    return Validity(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false, [gtNotBefore, gtNotAfter]);
}

shared class SubjectPublicKeyInfo<out P = Asn1Value<Anything>>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Sequ<[AlgorithmIdentifier<P>, BitString]>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        given P satisfies Asn1Value<Anything>
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    [AlgorithmIdentifier<P>, BitString] elements;
}

shared SubjectPublicKeyInfo<P> subjectPublicKeyInfo<P>(AlgorithmIdentifier<P> algorithmIdentifier, BitString bitString, Tag tag = UniversalTag.sequence)
        given P satisfies Asn1Value<Anything>
{
    value x = encodeAsn1Sequence([algorithmIdentifier, bitString], [Option.mandatory, Option.mandatory], tag);
    assert (!is EncodingError x);
    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = x;
    return SubjectPublicKeyInfo(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false, [algorithmIdentifier, bitString]);
}

shared class Extensions(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1SequenceOf<Extension>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    Extension[] elements;
}

shared class Extension(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Sequ<[ObjectIdentifier, Asn1Boolean, OctetString]>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    [ObjectIdentifier, Asn1Boolean, OctetString] elements;
}

shared void tCert()
{
    value keyBits = bitStringFromBytes([1.byte, 2.byte]);
    if (is EncodingError keyBits) {
        print(keyBits.message);
        return;
    }
    value subPKI = subjectPublicKeyInfo(sha256WithRsaSsaPssAndMgf1Sha256, keyBits);
    print(subPKI.encoded);
    print(subPKI.asn1String);
    
    value notBefore = parseZoneDateTime("2016-05-03T14:28:32Z")?.instant;
    assert (exists notBefore);
    value notAfter = parseZoneDateTime("2016-05-18T03:54:01Z")?.instant;
    assert (exists notAfter);
    value certValidity = validity(notBefore, notAfter);
    print(certValidity.encoded);
    print(certValidity.asn1String);
}

shared void tCert2()
{
}
