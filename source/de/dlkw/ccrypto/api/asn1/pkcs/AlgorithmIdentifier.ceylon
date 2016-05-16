import de.dlkw.ccrypto.api.asn1 {
    ObjectIdentifier,
    Asn1Sequence,
    Asn1Value,
    objectIdentifier,
    asn1Null,
    encodeAsn1Sequence,
    EncodingError,
    Option,
    IdentityInfo,
    Tag,
    UniversalTag,
    Asn1Null,
    Descriptor,
    Decoder,
    SequenceDecoder,
    objectIdentifierDecoder,
    DecodingError
}

"""
   Algorithm identifier structure for cryptographic algorithms.
   
   This reflects the AlgorithmIdentifier ASN.1 structure defined in PKCS #1 v2.2,
   which is about the same as the older ASN.1 form from X.509:
   ```asn1
   AlgorithmIdentifier ::= SEQUENCE {
       algorithm OBJECT IDENTIFIER,
       parameters ANY DEFINED BY algorithm OPTIONAL
   }
   ```
   """
shared class AlgorithmIdentifier<out Parameters = Asn1Value<Anything>>
        extends Asn1Sequence<[ObjectIdentifier, Parameters | Asn1Null]>
        given Parameters satisfies Asn1Value<Anything>
{
    shared new direct(Byte[] encoded, IdentityInfo identityInfo, Integer lengthOctetsOffset, Integer contentOctetsOffset, Boolean violatesDer, [ObjectIdentifier, Parameters | Asn1Null] valu)
            extends super.internal(encoded, identityInfo, lengthOctetsOffset,  contentOctetsOffset, violatesDer, valu)
    {}
    
    shared ObjectIdentifier objectIdentifier => val[0];
    shared Parameters | Asn1Null parameters => val[1];
}

shared AlgorithmIdentifier<Parameters> algorithmIdentifier<Parameters>(ObjectIdentifier oid, Parameters parameters, Tag tag = UniversalTag.sequence)
        given Parameters satisfies Asn1Value<Anything>
{
    value x = encodeAsn1Sequence([oid, parameters], [Option.mandatory, asn1Null()], tag);
    assert (!is EncodingError x);
    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = x;
    return AlgorithmIdentifier<Parameters>.direct(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false, [oid, parameters]);
}

shared class AlgorithmIdentifierDecoder<P>(Descriptor<P> parameterDescriptor)
        extends Decoder<AlgorithmIdentifier<P>>()
        given P satisfies Asn1Value<Anything>
        {
    // FIXME tag of desc, make default tag of decoder
    value delegate = SequenceDecoder<[ObjectIdentifier, P | Asn1Null]>([Descriptor<ObjectIdentifier>(UniversalTag.objectIdentifier, (_)=>objectIdentifierDecoder), Descriptor<P | Asn1Null>(parameterDescriptor.tag, parameterDescriptor.decoder, asn1Null())]);
    
    shared actual [AlgorithmIdentifier<P>, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        value x = delegate.decodeGivenTagAndLength(input, offset, identityInfo, length, identityOctetsOffset, lengthOctetsOffset, violatesDer);
        if (is DecodingError x) {
            return x;
        }
        value [seq, nextPos] = x;
        violatesDer ||= seq.violatesDer;
        
        value erg = AlgorithmIdentifier<P>.direct(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset, offset, violatesDer, seq.val);
        return [erg, nextPos];
    }
    
}


shared ObjectIdentifier id_sha1 = objectIdentifier([1, 3, 14, 3, 2, 26]);

ObjectIdentifier pkcs1Oid = objectIdentifier([1, 2, 840, 113549, 1, 1]);
shared ObjectIdentifier id_sha256 = objectIdentifier([2, 16, 840, 1, 101, 3, 4, 2, 1]);

shared ObjectIdentifier rsaSsaPssOid = pkcs1Oid.withTrailing(10);
shared ObjectIdentifier mgf1Oid = pkcs1Oid.withTrailing(8);

shared AlgorithmIdentifier sha1AlgId = algorithmIdentifier(id_sha1, asn1Null());
shared AlgorithmIdentifier sha256AlgId = algorithmIdentifier(id_sha256, asn1Null());

