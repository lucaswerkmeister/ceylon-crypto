import de.dlkw.ccrypto.asn1 {
    OctetString,
    IdentityInfo,
    encodeAsn1Sequence,
    EncodingError,
    Option,
    Tag,
    UniversalTag,
    octetString,
    GenericAsn1Value,
    Decoder,
    DecodingError,
    Asn1Value,
    Descriptor,
    SequenceDecoder,
    OctetStringDecoder,
    Asn1Sequ
}

shared class DigestInfo<P>(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer, valu)
        extends Asn1Sequ<[AlgorithmIdentifier<P>, OctetString]>(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer, valu)
        given P satisfies Asn1Value<Anything>
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentOctetsOffset;
    Boolean violatesDer;
    [AlgorithmIdentifier<P>, OctetString] valu;
    
    shared AlgorithmIdentifier<P> algorithmIdentifier => valu[0];
    shared Byte[] digestValue => valu[1].val;
}

shared DigestInfo<P> digestInfo<P>(AlgorithmIdentifier<P> algorithmIdentifier, Byte[] digestValue, Tag tag = UniversalTag.sequence)
        given P satisfies Asn1Value<Anything>
{
    value valu = [algorithmIdentifier, octetString(digestValue)];
    value x = encodeAsn1Sequence(valu, [Option.mandatory, Option.mandatory], tag);
    assert (!is EncodingError x);
    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = x;
    return DigestInfo<P>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false, valu);
}

shared class DigestInfoDecoder<P>(parameterSelector, tag = UniversalTag.sequence)
        extends Decoder<DigestInfo<P>>(tag)
        given P satisfies Asn1Value<Anything>
{
    <Decoder<P>|DecodingError>(GenericAsn1Value?[]) parameterSelector;
    Tag tag;

    value delegate = SequenceDecoder<[AlgorithmIdentifier<P>, OctetString]>([
        Descriptor<AlgorithmIdentifier<P>>((_)=>AlgorithmIdentifierDecoder(parameterSelector)),
        Descriptor<OctetString>((_)=>OctetStringDecoder())
    ]);

    shared actual [DigestInfo<P>, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        value x = delegate.decodeGivenTagAndLength(input, offset, identityInfo, length, identityOctetsOffset, lengthOctetsOffset, violatesDer);
        if (is DecodingError x) {
            return x;
        }
        value [seq, nextPos] = x;
        violatesDer ||= seq.violatesDer;
        
        value erg = DigestInfo<P>(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset - identityOctetsOffset, offset - identityOctetsOffset, violatesDer, seq.val);
        return [erg, nextPos];
    }
}