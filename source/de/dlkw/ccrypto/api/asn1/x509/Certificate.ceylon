import de.dlkw.ccrypto.asn1 {
    Asn1Sequence,
    IdentityInfo,
    BitString,
    TaggedValue,
    Asn1Integer,
    GenericAsn1Value,
    GeneralizedTime,
    Asn1Set,
    UTCTime,
    ObjectIdentifier,
    Asn1Value
}
import de.dlkw.ccrypto.api.asn1.pkcs {
    AlgorithmIdentifier
}

class Certificate(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Sequence<[TBSCertificate, AlgorithmIdentifier<>, BitString]>.internal(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    [TBSCertificate, AlgorithmIdentifier<>, BitString] elements;
}

class TBSCertificate(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Sequence<[TaggedValue<Asn1Integer>, Asn1Integer, AlgorithmIdentifier<>, RDNSequence, Validity, RDNSequence, SubjectPublicKeyInfo, BitString, BitString, Extensions]>.internal(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    [TaggedValue<Asn1Integer>, Asn1Integer, AlgorithmIdentifier<>, RDNSequence, Validity, RDNSequence, SubjectPublicKeyInfo, BitString, BitString, Extensions] elements;
}

class RDNSequence(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Sequence<RelativeDistinguishedName[]>.internal(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    [] elements;
}

class RelativeDistinguishedName(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Set<AttributeValueAssertion<>[]>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    [] elements;
}

shared class AttributeValueAssertion<out Parameters = Asn1Value<Anything>>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Sequence<[ObjectIdentifier, Parameters?]>.internal(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        given Parameters satisfies Asn1Value<Anything>
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    [ObjectIdentifier, Parameters] elements;
}

class Validity(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Sequence<Time[]>.internal(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    [] elements;
}

alias Time => UTCTime | GeneralizedTime;

class SubjectPublicKeyInfo(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Sequence<[AlgorithmIdentifier<>, BitString]>.internal(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    [AlgorithmIdentifier<>, BitString] elements;
}

class Extensions(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Sequence<Extension[]>.internal(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    Extension[] elements;
}

class Extension(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer) extends GenericAsn1Value(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
}
