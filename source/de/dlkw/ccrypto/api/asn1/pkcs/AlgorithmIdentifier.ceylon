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
    Asn1Null
}

shared class AlgorithmIdentifier<out Parameters = Asn1Value<Anything>>
        extends Asn1Sequence<[ObjectIdentifier, Parameters]>
        given Parameters satisfies Asn1Value<Anything>
        {
    shared new direct(Byte[] encoded, IdentityInfo identityInfo, Integer lengthOctetsOffset, Integer contentOctetsOffset, Boolean violatesDer, [ObjectIdentifier, Parameters] valu)
            extends super.internal(encoded, identityInfo, lengthOctetsOffset,  contentOctetsOffset, violatesDer, valu)
    {}
}

shared AlgorithmIdentifier<Parameters> algorithmIdentifier<Parameters>(ObjectIdentifier oid, Parameters parameters, Tag tag = UniversalTag.sequence)
        given Parameters satisfies Asn1Value<Anything>
{
    value x = encodeAsn1Sequence([oid, parameters], [Option.mandatory, asn1Null()], tag);
    assert (!is EncodingError x);
    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = x;
    return AlgorithmIdentifier<Parameters>.direct(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false, [oid, parameters]);
}

shared ObjectIdentifier id_sha1 = objectIdentifier([1, 3, 14, 3, 2, 26]);

ObjectIdentifier pkcs1Oid = objectIdentifier([1, 2, 840, 113549, 1, 1]);
shared ObjectIdentifier id_sha256 = objectIdentifier([2, 16, 840, 1, 101, 3, 4, 2, 1]);

shared ObjectIdentifier rsaSsaPssOid = pkcs1Oid.withTrailing(10);
shared ObjectIdentifier mgf1Oid = pkcs1Oid.withTrailing(8);

