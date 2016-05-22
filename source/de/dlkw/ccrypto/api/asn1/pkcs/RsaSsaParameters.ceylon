import de.dlkw.ccrypto.api.asn1 {
    asn1Null,
    Asn1Integer,
    asn1Integer,
    encodeAsn1Sequence,
    Tag,
    UniversalTag,
    Asn1Sequence,
    taggedValue,
    TaggedValue,
    IdentityInfo,
    EncodingError,
    Asn1Value,
    DecodingError,
    TaggedValueDecoder,
    Descriptor,
    Decoder,
    Asn1Null,
    SequenceDecoder,
    Asn1IntegerDecoder
}

"""
   Algorithm parameters for the RSASSA-PSS signature scheme.
   
   This reflects the following ASN.1 structure defined in PKCS #1 v2.2:
   ```asn1
   RSASSA-PSS-params ::= SEQUENCE {
       hashAlgorithm    [0] HashAlgorithm    DEFAULT sha1
       maskGenAlgorithm [1] MaskGenAlgorithm DEFAULT mgf1SHA1
       saltLength       [2] INTEGER          DEFAULT 20
       trailerField     [3] TrailerField     DEFAULT trailerFieldBC
   }
   ```
   where `sha1` is the `AlgorithmIdentifier` of the SHA-1 message digest algorithm
   (object identifier `1.3.14.3.2.26`) and `mgf1SHA1` is the `AlgorithmIdentifier` of the
   MGF1 mask generating function (object identifier `1.2.840.113549.1.8`) using SHA-1 as hash.
   `trailerFieldBC` is a name for 1, the only allowed field (according to PKCS #1).
"""
shared class RsaSsaParameters<out HashAlgIdParams = Asn1Value<Anything>, out MgfAlgIdParams = Asn1Value<Anything>>
        extends Asn1Sequence<[TaggedValue<AlgorithmIdentifier<HashAlgIdParams>>, TaggedValue<AlgorithmIdentifier<MgfAlgIdParams>>, TaggedValue<Asn1Integer>, TaggedValue<Asn1Integer>]>
        given HashAlgIdParams satisfies Asn1Value<Anything>
        given MgfAlgIdParams satisfies Asn1Value<Anything>
{
    shared new (encoded, IdentityInfo identityInfo, Integer lengthOctetsOffset, Integer contentOctetsOffset, violatesDer, val)
            extends super.internal(encoded, identityInfo, lengthOctetsOffset,  contentOctetsOffset, violatesDer, val)
    {
        Byte[] encoded;
        Boolean violatesDer;
        [TaggedValue<AlgorithmIdentifier<HashAlgIdParams>>, TaggedValue<AlgorithmIdentifier<MgfAlgIdParams>>, TaggedValue<Asn1Integer>, TaggedValue<Asn1Integer>] val;
    }
    
    shared AlgorithmIdentifier<HashAlgIdParams> digestAlgorithmId => val[0].val;
    shared AlgorithmIdentifier<MgfAlgIdParams> mgfAlgorithmId => val[1].val;
    shared Integer saltLength => val[2].val.val;
}

"Creates an instance of RsaSsaParameters with the given values. According to PKCS #1, the
 only allowed value for `trailerField` is 1, indicating a trailer field octet `0xbc` is used
 in the algorithm."
shared RsaSsaParameters<HashAlgIdParams, MgsAlgIdParams> rsaSsaParams<HashAlgIdParams, MgsAlgIdParams>(
            AlgorithmIdentifier<HashAlgIdParams> hashAlgorithm,
            AlgorithmIdentifier<MgsAlgIdParams> mgfAlgorithm,
            Integer saltLength = 20,
            Integer trailerField = 1,
            Tag tag = UniversalTag.sequence)
        given HashAlgIdParams satisfies Asn1Value<Anything>
        given MgsAlgIdParams satisfies Asn1Value<Anything>
{
    value aHashAlgorithm = taggedValue(hashAlgorithm, Tag(0));
    value aMgfAlgorithm = taggedValue(mgfAlgorithm, Tag(1));
    value aSaltLength = taggedValue(asn1Integer(saltLength), Tag(2));
    value aTrailerField = taggedValue(asn1Integer(trailerField), Tag(3));
    
    // encode the sequence, using the default values from the specification
    value x = encodeAsn1Sequence([aHashAlgorithm, aMgfAlgorithm, aSaltLength, aTrailerField], [
            taggedValue(rsaSsaDefaultHashParameter, Tag(0)),
            taggedValue(rsaSsaDefaultMgfParameter, Tag(1)),
            taggedValue(asn1Integer(20), Tag(2)),
            taggedValue(asn1Integer(1), Tag(3))
        ], tag);
    assert (!is EncodingError x);

    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = x;
    
    return RsaSsaParameters<HashAlgIdParams, MgsAlgIdParams>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false, [aHashAlgorithm, aMgfAlgorithm, aSaltLength, aTrailerField]);
}

shared class RsaSsaParamsDecoder<out HP1, out HP2>(hashAlgIdDescriptor, mgfAlgIdDescriptor, Tag tag = UniversalTag.sequence)
        extends Decoder<RsaSsaParameters<HP1, HP2>>(tag)
        given HP1 satisfies Asn1Value<Anything>
        given HP2 satisfies Asn1Value<Anything>
{
    Descriptor<AlgorithmIdentifier<HP1>> hashAlgIdDescriptor;
    Descriptor<AlgorithmIdentifier<HP2>> mgfAlgIdDescriptor;
    
    assert (is AlgorithmIdentifier<HP1> rsaSsaDefaultHashParameter);
    assert (is AlgorithmIdentifier<HP2> rsaSsaDefaultMgfParameter);
    
    value delegate = SequenceDecoder<[TaggedValue<AlgorithmIdentifier<HP1>>, TaggedValue<AlgorithmIdentifier<HP2>>, TaggedValue<Asn1Integer>, TaggedValue<Asn1Integer>]>([
        Descriptor<TaggedValue<AlgorithmIdentifier<HP1>>>(
        // use let to show type in IDE hover
        (y)
            {
            Decoder<AlgorithmIdentifier<HP1>>|DecodingError v1v = hashAlgIdDescriptor.decoder(y);
            if (is Decoder<AlgorithmIdentifier<HP1>> v1v) {
                return TaggedValueDecoder(Tag(0), v1v);
            }
            else {
                return v1v;
            }
        }, taggedValue(rsaSsaDefaultHashParameter, Tag(0))), 
        Descriptor<TaggedValue<AlgorithmIdentifier<HP2>>>( 
            (y)
            {
                value vv = mgfAlgIdDescriptor.decoder(y);
                if (is Decoder<AlgorithmIdentifier<HP2>> vv) {
                    return TaggedValueDecoder(Tag(1), vv);
                }
                else {
                    return vv;
                }
            }, taggedValue(rsaSsaDefaultMgfParameter, Tag(1))),
            Descriptor<TaggedValue<Asn1Integer>>((_)=>TaggedValueDecoder(Tag(2), Asn1IntegerDecoder()), taggedValue(asn1Integer(20), Tag(2))),
            Descriptor<TaggedValue<Asn1Integer>>((_)=>TaggedValueDecoder(Tag(3), Asn1IntegerDecoder()), taggedValue(asn1Integer(1), Tag(3)))
        ]);

    shared actual [RsaSsaParameters<HP1,HP2>, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer contentStart, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        value x = delegate.decodeGivenTagAndLength(input, contentStart, identityInfo, length, identityOctetsOffset, lengthOctetsOffset, violatesDer);
        if (is DecodingError x) {
            return x;
        }
        value [seq, nextPos] = x;
        violatesDer ||= seq.violatesDer;
        
        value dec = seq.val;
        //assert (is [TaggedValue<AlgorithmIdentifier<HP1>>, TaggedValue<AlgorithmIdentifier<HP2>>, TaggedValue<Asn1Integer>, TaggedValue<Asn1Integer>] dec);
        
        value erg = RsaSsaParameters<HP1, HP2>(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset - identityOctetsOffset, contentStart - identityOctetsOffset, violatesDer, dec);
        return [erg, nextPos];
    }
}

"The default algorithm identifier for the hash algorithm, SHA-1."
shared AlgorithmIdentifier<Asn1Null> rsaSsaDefaultHashParameter = algorithmIdentifier(id_sha1, asn1Null());

"The default algorithm identifier for the mask generating function, MGF1 with SHA-1."
shared AlgorithmIdentifier<AlgorithmIdentifier<Asn1Null>> rsaSsaDefaultMgfParameter = algorithmIdentifier(mgf1Oid, rsaSsaDefaultHashParameter);
