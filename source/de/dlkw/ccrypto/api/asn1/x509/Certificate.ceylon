import ceylon.time {
    Instant
}
import ceylon.time.iso8601 {
    parseZoneDateTime
}

import de.dlkw.ccrypto.api.asn1.pkcs {
    AlgorithmIdentifier,
    sha256WithRsaSsaPssAndMgf1Sha256,
    AlgorithmIdentifierAnySwitch,
    AlgorithmIdentifierDecoder
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
    Asn1Sequence,
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
    taggedValue,
    asn1Integer,
    DecodingError,
    Decoder,
    SequenceDecoder,
    Descriptor,
    Asn1IntegerDecoder,
    BitStringDecoder,
    GenericAsn1Value,
    TaggedValueDecoder,
    GeneralizedTimeDecoder,
    SequenceOfDecoder,
    SetOfDecoder,
    ObjectIdentifierDecoder,
    GenericAsn1ValueDecoder,
    Asn1BooleanDecoder,
    OctetStringDecoder,
    asn1Boolean,
    ChoiceDecoder,
    UTCTimeDecoder,
    generalizedTimeFromInstant,
    utcTimeFromInstant
}
import ceylon.time.timezone {
    ZoneDateTime,
    timeZone
}

shared class Certificate(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Sequence<[TBSCertificate, AlgorithmIdentifier<>, BitString]>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    [TBSCertificate, AlgorithmIdentifier<>, BitString] elements;

    shared Integer version => val[0].val[0].val.val;
    shared Integer serialNumber => val[0].val[1].val;
    shared AlgorithmIdentifier<> signatureAlgorithm => val[0].val[2];
    shared RDNSequence issuer => val[0].val[3];
    shared Instant validNotBefore => val[0].val[4].notBefore;
    shared Instant validNotAfter => val[0].val[4].notAfter;
    shared RDNSequence subject => val[0].val[5];
    shared SubjectPublicKeyInfo<> subjectPublicKeyInfo => val[0].val[6];
    shared BitString? issuerUniqueId => val[0].val[7];
    shared BitString? subjectUniqueId => val[0].val[8];
    shared Extensions? extensions => val[0].val[9]?.val;
    
    shared TBSCertificate tbsCertificate => val[0];
    shared BitString signatureValue => val[2];
}

shared Certificate | EncodingError certificate(tbsCertificate, algorithmIdentifier, signatureValue, Tag tag = UniversalTag.sequence)
{
    TBSCertificate tbsCertificate;
    AlgorithmIdentifier<> algorithmIdentifier;
    Byte[] signatureValue;

    if (tbsCertificate.tag != UniversalTag.sequence) {
        return EncodingError("wrong tag in tbsCertificate");
    }
    
    value bitString = bitStringFromBytes(signatureValue);
    assert (!is EncodingError bitString);
    value enc = encodeAsn1Sequence([tbsCertificate, algorithmIdentifier, bitString], [Option.mandatory, Option.mandatory, Option.mandatory], tag);
    assert (!is EncodingError enc);
    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = enc;
    return Certificate(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false,
        [tbsCertificate, algorithmIdentifier, bitString]);
}

shared class TBSCertificate(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Sequence<[TaggedValue<Asn1Integer>, Asn1Integer, AlgorithmIdentifier<>, RDNSequence, Validity, RDNSequence, SubjectPublicKeyInfo<Asn1Value<Anything>>, BitString?, BitString?, TaggedValue<Extensions>?]>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    [TaggedValue<Asn1Integer>, Asn1Integer, AlgorithmIdentifier<>, RDNSequence, Validity, RDNSequence, SubjectPublicKeyInfo<Asn1Value<Anything>>, BitString?, BitString?, TaggedValue<Extensions>?] elements;
    
    shared Integer version => val[0].val.val;
    shared Integer serialNumber => val[1].val;
    shared AlgorithmIdentifier<> signatureAlgorithm => val[2];
    shared RDNSequence issuer => val[3];
    shared Instant validNotBefore => val[4].notBefore;
    shared Instant validNotAfter => val[4].notAfter;
    shared RDNSequence subject => val[5];
    shared SubjectPublicKeyInfo<> subjectPublicKeyInfo => val[6];
    shared BitString? issuerUniqueId => val[7];
    shared BitString? subjectUniqueId => val[8];
    shared Extensions? extensions => val[9]?.val;
}

shared TBSCertificate | EncodingError tbsCertificate(version, serialNumber, signature, issuer, notBefore, notAfter,
     subject, subjectPublicKeyInfo, extensions)
{
    Integer version;
    if (!(1 <= version <= 3)) {
        return EncodingError("version out of range");
    }
    
    Integer serialNumber;

    AlgorithmIdentifier<> signature;
    // TODO really need asn1 value without tag here to set and ensure the right tag!
    if (signature.identityInfo.tag != UniversalTag.sequence) {
        return EncodingError("wrong tag in signature");
    }
    
    RDNSequence issuer;
    // TODO really need asn1 value without tag here to set and ensure the right tag!
    if (issuer.identityInfo.tag != UniversalTag.sequence) {
        return EncodingError("wrong tag in issuer");
    }
    
    Instant notBefore;
    Instant notAfter;
    if (!notBefore.smallerThan(notAfter)) {
        return EncodingError("notBefore must lie before notAfter");
    }
    
    RDNSequence subject;
    // TODO really need asn1 value without tag here to set and ensure the right tag!
    if (subject.identityInfo.tag != UniversalTag.sequence) {
        return EncodingError("wrong tag of subject");
    }

    SubjectPublicKeyInfo<> subjectPublicKeyInfo;
    // TODO really need asn1 value without tag here to set and ensure the right tag!
    if (subjectPublicKeyInfo.identityInfo.tag != UniversalTag.sequence) {
        return EncodingError("wrong tag of subjectPublicKeyInfo");
    }

    Extensions? extensions;
    if (exists extensions) {
        // TODO really need asn1 value without tag here to set and ensure the right tag!
        if (extensions.identityInfo.tag != UniversalTag.sequence) {
            return EncodingError("wrong tag of extensions");
        }
    }
    
    value asn1Version = taggedValue(asn1Integer(version), Tag(0));
    value asn1Serial = asn1Integer(serialNumber);
    value certValidity = validity(notBefore, notAfter);
    if (is EncodingError certValidity) {
        return certValidity;
    }
    // TODO issuer and subject alternate names with expl. tags 1 and 2
    value asn1Extensions = if (exists extensions)
        then taggedValue(extensions, Tag(3))
        else null;
    
    value enc = encodeAsn1Sequence([asn1Version, asn1Serial, signature, issuer, certValidity, subject,
            subjectPublicKeyInfo, null, null, asn1Extensions],
            [asn1Integer(1), Option.mandatory, Option.mandatory, Option.mandatory, Option.mandatory, Option.mandatory,
            Option.mandatory, Option.optional, Option.optional, Option.optional],
            UniversalTag.sequence);
    assert (!is EncodingError enc);
    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = enc;
    return TBSCertificate(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false,
        [asn1Version, asn1Serial, signature, issuer, certValidity, subject, subjectPublicKeyInfo, null, null, asn1Extensions]);
}

shared class CertificateDecoder(//Descriptor<Asn1Value<Anything>> keyAlgIdDescriptor,
    AlgorithmIdentifierAnySwitch supportedSigAlgorithms, AlgorithmIdentifierAnySwitch supportedNameAttributes,
    AlgorithmIdentifierAnySwitch supportedKeyAlgorithms, Tag tag = UniversalTag.sequence)
        extends Decoder<Certificate>(tag)
{
    value delegate = SequenceDecoder<[
            TBSCertificate,
            AlgorithmIdentifier<>,
            BitString
        ]>
        ([
            Descriptor<TBSCertificate>((_)=>TBSCertificateDecoder(supportedSigAlgorithms, supportedNameAttributes, supportedKeyAlgorithms)),
            Descriptor<AlgorithmIdentifier<Asn1Value<Anything>>>((_)=>AlgorithmIdentifierDecoder<Asn1Value<Anything>>(supportedSigAlgorithms.selectDecoder)),
            //Descriptor<AlgorithmIdentifier<>>((_)=>AlgorithmIdentifierDecoder<Asn1Value<Anything>>(
            //    supportedKeyAlgorithms.selectDecoder)),
            Descriptor<BitString>((_)=>BitStringDecoder())
    ]);

    shared actual [Certificate, Integer]|DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        value x = delegate.decodeGivenTagAndLength(input, offset, identityInfo, length, identityOctetsOffset, lengthOctetsOffset, violatesDer);
        if (is DecodingError x) {
            return x;
        }
        value [seq, nextPos] = x;
        violatesDer ||= seq.violatesDer;
        
        value decoded = seq.val;
        
        if (decoded[1] != decoded[0].signatureAlgorithm) {
            return DecodingError(offset, "Signature algorithm id in outer certificat does not match value in tbsCertificate");
        }
        value tbs = Certificate(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset, offset, violatesDer, decoded);
        return [tbs, nextPos];
    }
}

shared class TBSCertificateDecoder(AlgorithmIdentifierAnySwitch supportedSigAlgorithms, AlgorithmIdentifierAnySwitch supportedNameAttributes,
    AlgorithmIdentifierAnySwitch supportedKeyAlgorithms, Tag tag = UniversalTag.sequence)
        extends Decoder<TBSCertificate>(tag)
{
    value delegate = SequenceDecoder<[
        TaggedValue<Asn1Integer>,
        Asn1Integer,
        AlgorithmIdentifier<>,
        RDNSequence,
        Validity,
        RDNSequence,
        SubjectPublicKeyInfo<>,
        GenericAsn1Value?,
        GenericAsn1Value?,
        TaggedValue<Extensions>?
//        TaggedValue<GenericAsn1Value>?
    ]>([
        Descriptor((_)=>TaggedValueDecoder(Tag(0), Asn1IntegerDecoder())),
        Descriptor((_)=>Asn1IntegerDecoder()),
        Descriptor((_)=>AlgorithmIdentifierDecoder<Asn1Value<Anything>>(supportedSigAlgorithms.selectDecoder)),
        Descriptor((_)=>RDNSequenceDecoder(supportedNameAttributes)),
        Descriptor((_)=>ValidityDecoder()),
        Descriptor((_)=>RDNSequenceDecoder(supportedNameAttributes)),
        Descriptor((_)=>SubjectPublicKeyInfoDecoder<Asn1Value<Anything>>(supportedKeyAlgorithms)),
        Descriptor((_)=>GenericAsn1ValueDecoder(Tag(1)), Option.optional),
        Descriptor((_)=>GenericAsn1ValueDecoder(Tag(2)), Option.optional),
        Descriptor<TaggedValue<Extensions>>((_)=>TaggedValueDecoder(Tag(3), ExtensionsDecoder()), Option.optional)
//        Descriptor((_)=>TaggedValueDecoder(Tag(3), GenericAsn1ValueDecoder()), Option.optional)
    ]);
    
    shared actual [TBSCertificate, Integer]|DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        value x = delegate.decodeGivenTagAndLength(input, offset, identityInfo, length, identityOctetsOffset, lengthOctetsOffset, violatesDer);
        if (is DecodingError x) {
            return x;
        }
        value [seq, nextPos] = x;
        violatesDer ||= seq.violatesDer;
        
        value decoded = seq.val;
        TaggedValue<Asn1Integer> version = decoded[0];
        if (!(1 <= version.val.val <= 3)) {
            return DecodingError(offset, "version out of range");
        }

        Asn1Integer serialNumber = decoded[1];
        AlgorithmIdentifier<> signature = decoded[2];
        RDNSequence issuer = decoded[3];
        Validity certValidity = decoded[4];
        RDNSequence subject = decoded[5];
        SubjectPublicKeyInfo<> subjectPublicKeyInfo = decoded[6];
        GenericAsn1Value? a = decoded[7];
        GenericAsn1Value? b = decoded[8];
        //TaggedValue<Extensions> extensions = decoded[9];
        TaggedValue<GenericAsn1Value>? extensions = decoded[9];
        
        print("extensions: " + (extensions?.asn1String else "none"));

        value tbs = TBSCertificate(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset, offset, violatesDer, [
                version,
                serialNumber,
                signature,
                issuer,
                certValidity,
                subject,
                subjectPublicKeyInfo,
                null,
                null,
                null//extensions
            ]);
        return [tbs, nextPos];
    }
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

shared class RDNSequenceDecoder(AlgorithmIdentifierAnySwitch anySwitch, Tag tag = UniversalTag.sequence)
        extends Decoder<RDNSequence>(tag)
{
    value delegate = SequenceOfDecoder<RelativeDistinguishedName>
            (RelativeDistinguishedNameDecoder(anySwitch));
    
    shared actual [RDNSequence, Integer]|DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        value x = delegate.decodeGivenTagAndLength(input, offset, identityInfo, length, identityOctetsOffset, lengthOctetsOffset, violatesDer);
        if (is DecodingError x) {
            return x;
        }
        value [seq, nextPos] = x;
        violatesDer ||= seq.violatesDer;
        
        value decoded = seq.val;
        value r = RDNSequence(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset, offset, violatesDer, decoded);
        return [r, nextPos];
    }
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

shared class RelativeDistinguishedNameDecoder(AlgorithmIdentifierAnySwitch anySwitch, Tag tag = UniversalTag.set)
        extends Decoder<RelativeDistinguishedName>(tag)
{
    value delegate = SetOfDecoder<AttributeValueAssertion<>>
            (AttributeValueAssertionDecoder<Asn1Value<Anything>>(anySwitch));
    
    shared actual [RelativeDistinguishedName, Integer]|DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        value x = delegate.decodeGivenTagAndLength(input, offset, identityInfo, length, identityOctetsOffset, lengthOctetsOffset, violatesDer);
        if (is DecodingError x) {
            return x;
        }
        value [seq, nextPos] = x;
        violatesDer ||= seq.violatesDer;
        
        value decoded = seq.val;
        value r = RelativeDistinguishedName(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset, offset, violatesDer, decoded);
        return [r, nextPos];
    }
}

shared class AttributeValueAssertion<out Parameters = Asn1Value<Anything>>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Sequence<[ObjectIdentifier, Parameters?]>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
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

shared class AttributeValueAssertionDecoder<ValueType>(AlgorithmIdentifierAnySwitch anySwitch, Tag tag = UniversalTag.sequence)
        extends Decoder<AttributeValueAssertion<ValueType>>(tag)
        given ValueType satisfies Asn1Value<Anything>
{
    value delegate = SequenceDecoder<[ObjectIdentifier, ValueType]>
            ([Descriptor((_)=>ObjectIdentifierDecoder()), Descriptor(anySwitch.selectDecoder)]);
    
    shared actual [AttributeValueAssertion<ValueType>, Integer]|DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        value x = delegate.decodeGivenTagAndLength(input, offset, identityInfo, length, identityOctetsOffset, lengthOctetsOffset, violatesDer);
        if (is DecodingError x) {
            return x;
        }
        value [seq, nextPos] = x;
        violatesDer ||= seq.violatesDer;
        
        value decoded = seq.val;
        value r = AttributeValueAssertion<ValueType>(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset, offset, violatesDer, decoded);
        return [r, nextPos];
    }
}

shared class Validity(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Sequence<Time[2]>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
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
            assert (is ZoneDateTime zdt = val.dateTime);
            return zdt.instant;
        }
        else {
            // UTCTime
            assert (is ZoneDateTime zdt = val.dateTime);
            return zdt.instant;
        }
    }
    
    shared Instant notAfter
    {
        value val = elements[1];
        if (is GeneralizedTime val) {
            assert (is ZoneDateTime zdt = val.dateTime);
            return zdt.instant;
        }
        else {
            // UTCTime
            assert (is ZoneDateTime zdt = val.dateTime);
            return zdt.instant;
        }
    }
}

shared alias Time => UTCTime | GeneralizedTime;

shared Validity|EncodingError validity(Instant notBefore, Instant notAfter, Tag tag = UniversalTag.sequence)
{
    // according to PKIX (RFC5280. 4.1.2.5), encode all dates before the year 2050
    // as UTCTime, and all dates in or after the year 2050 as GeneralizedTime.
    
    UTCTime | GeneralizedTime tNotBefore;
    if (notBefore.zoneDateTime(timeZone.utc).year < 2050) {
        value t = utcTimeFromInstant(notBefore);
        if (is EncodingError t) {
            return t;
        }
        tNotBefore = t;
    }
    else {
        value t = generalizedTimeFromInstant(notBefore);
        if (is EncodingError t) {
            return t;
        }
        tNotBefore = t;
    }

    UTCTime | GeneralizedTime tNotAfter;
    if (notAfter.zoneDateTime(timeZone.utc).year < 2050) {
        value t = utcTimeFromInstant(notAfter);
        if (is EncodingError t) {
            return t;
        }
        tNotAfter = t;
    }
    else {
        value t = generalizedTimeFromInstant(notAfter);
        if (is EncodingError t) {
            return t;
        }
        tNotAfter = t;
    }

    value x = encodeAsn1Sequence([tNotBefore, tNotAfter], [Option.mandatory, Option.mandatory], tag);
    assert (!is EncodingError x);
    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = x;
    return Validity(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false, [tNotBefore, tNotAfter]);
}

shared class ValidityDecoder(Tag tag = UniversalTag.sequence)
        extends Decoder<Validity>(tag)
{
    value delegate = SequenceDecoder<[
        <UTCTime | GeneralizedTime>,
        <UTCTime | GeneralizedTime>
    ]>([
        Descriptor((_)=>ChoiceDecoder([UTCTimeDecoder(2049), GeneralizedTimeDecoder()])),
        Descriptor((_)=>ChoiceDecoder([UTCTimeDecoder(2049), GeneralizedTimeDecoder()]))
    ]);
    
    shared actual [Validity, Integer]|DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        value x = delegate.decodeGivenTagAndLength(input, offset, identityInfo, length, identityOctetsOffset, lengthOctetsOffset, violatesDer);
        if (is DecodingError x) {
            return x;
        }
        value [seq, nextPos] = x;
        violatesDer ||= seq.violatesDer;
        
        value decoded = seq.val;
        value r = Validity(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset, offset, violatesDer, decoded);
        return [r, nextPos];
    }
}

shared class SubjectPublicKeyInfo<out P = Asn1Value<Anything>>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Sequence<[AlgorithmIdentifier<P>, BitString]>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        given P satisfies Asn1Value<Anything>
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    [AlgorithmIdentifier<P>, BitString] elements;
    
    shared AlgorithmIdentifier<P> algorithmIdentifier => val[0];
    shared BitString encodedKey => val[1];
}

shared SubjectPublicKeyInfo<P> subjectPublicKeyInfo<P>(AlgorithmIdentifier<P> algorithmIdentifier, BitString bitString, Tag tag = UniversalTag.sequence)
        given P satisfies Asn1Value<Anything>
{
    value x = encodeAsn1Sequence([algorithmIdentifier, bitString], [Option.mandatory, Option.mandatory], tag);
    assert (!is EncodingError x);
    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = x;
    return SubjectPublicKeyInfo(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false, [algorithmIdentifier, bitString]);
}

shared class SubjectPublicKeyInfoDecoder<ValueType>(AlgorithmIdentifierAnySwitch anySwitch, Tag tag = UniversalTag.sequence)
        extends Decoder<SubjectPublicKeyInfo<ValueType>>(tag)
        given ValueType satisfies Asn1Value<Anything>
{
    value delegate = SequenceDecoder<[AlgorithmIdentifier<ValueType>, BitString]>
            ([Descriptor((_)=>AlgorithmIdentifierDecoder(anySwitch.selectDecoder)), Descriptor((_)=>BitStringDecoder())]);
    
    shared actual [SubjectPublicKeyInfo<ValueType>, Integer]|DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        value x = delegate.decodeGivenTagAndLength(input, offset, identityInfo, length, identityOctetsOffset, lengthOctetsOffset, violatesDer);
        if (is DecodingError x) {
            return x;
        }
        value [seq, nextPos] = x;
        violatesDer ||= seq.violatesDer;
        
        value decoded = seq.val;
        value r = SubjectPublicKeyInfo<ValueType>(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset, offset, violatesDer, decoded);
        return [r, nextPos];
    }
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

shared class ExtensionsDecoder(Tag tag = UniversalTag.sequence)
        extends Decoder<Extensions>(tag)
{
    value delegate = SequenceOfDecoder<Extension>
            (ExtensionDecoder());
    
    shared actual [Extensions, Integer]|DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        value x = delegate.decodeGivenTagAndLength(input, offset, identityInfo, length, identityOctetsOffset, lengthOctetsOffset, violatesDer);
        if (is DecodingError x) {
            return x;
        }
        value [seq, nextPos] = x;
        violatesDer ||= seq.violatesDer;
        
        value decoded = seq.val;
        value r = Extensions(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset, offset, violatesDer, decoded);
        return [r, nextPos];
    }
}

shared class Extension(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Sequence<[ObjectIdentifier, Asn1Boolean, OctetString]>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    [ObjectIdentifier, Asn1Boolean, OctetString] elements;
}

shared class ExtensionDecoder(Tag tag = UniversalTag.sequence)
        extends Decoder<Extension>(tag)
{
    value delegate = SequenceDecoder<[ObjectIdentifier, Asn1Boolean, OctetString]>
            ([Descriptor((_)=>ObjectIdentifierDecoder()), Descriptor((_)=>Asn1BooleanDecoder(), asn1Boolean(false)), Descriptor((_)=>OctetStringDecoder())]);
    
    shared actual [Extension, Integer]|DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        value x = delegate.decodeGivenTagAndLength(input, offset, identityInfo, length, identityOctetsOffset, lengthOctetsOffset, violatesDer);
        if (is DecodingError x) {
            return x;
        }
        value [seq, nextPos] = x;
        violatesDer ||= seq.violatesDer;
        
        value decoded = seq.val;
        value r = Extension(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset, offset, violatesDer, decoded);
        return [r, nextPos];
    }
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
    if (is EncodingError certValidity) {
        print(certValidity.message);
        return;
    }
    print(certValidity.encoded);
    print(certValidity.asn1String);
}
