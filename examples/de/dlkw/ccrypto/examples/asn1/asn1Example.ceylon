import de.dlkw.ccrypto.api.asn1 {
    Asn1Sequence,
    ObjectIdentifier,
    Asn1Value,
    EncodingError,
    DecodingError,
    SequenceDecoder,
    Descriptor,
    objectIdentifierDecoder,
    UniversalTag,
    Asn1Null,
    nullDecoder,
    asn1Null,
    objectIdentifier,
    encodeAsn1Sequence,
    TaggedValue,
    asn1Integer,
    taggedValue,
    Tag,
    Asn1Integer,
    Option,
    TagClass,
    Decoder,
    asn1IntegerDecoder
}
import de.dlkw.ccrypto.api.asn1old {
    hexdump
}

shared class AlgorithmIdentifier<Parameters>
        extends Asn1Sequence<[ObjectIdentifier, Parameters]>
        given Parameters satisfies Asn1Value<Anything>
{
    shared new direct(Byte[] encoded, Boolean violatesDer, [ObjectIdentifier, Parameters] val)
            extends super.internal(encoded, violatesDer, val){}
}

shared class AlgorithmIdentifierDecoder<P>(Descriptor<P> parameterDescriptor)
        extends SequenceDecoder<[ObjectIdentifier, P]>(
            [Descriptor<ObjectIdentifier>(UniversalTag.objectIdentifier, objectIdentifierDecoder), parameterDescriptor]
        )
        given P satisfies Asn1Value<Anything>
{
    shared actual [AlgorithmIdentifier<P>, Integer, Boolean]|DecodingError decodeGivenTag(Byte[] input, Integer offset, Integer identityOctetsOffset)
    {
        variable Boolean violatesDer = false;
        value x = super.decodeGivenTag(input, offset, identityOctetsOffset);
        if (is DecodingError x) {
            return x;
        }
        value [seq, nextPos, violates0] = x;
        violatesDer ||= violates0;
        
        value erg = AlgorithmIdentifier.direct(input[identityOctetsOffset .. nextPos - 1], violatesDer, seq.val);
        return [erg, nextPos, violatesDer];
    }
}

shared AlgorithmIdentifier<Parameters> algorithmIdentifier<Parameters>(ObjectIdentifier oid, Parameters parameters)
        given Parameters satisfies Asn1Value<Anything>
{
    value x = encodeAsn1Sequence([oid, parameters], [Option.mandatory, asn1Null()]);
    assert (!is EncodingError x);
    return AlgorithmIdentifier<Parameters>.direct(x, false, [oid, parameters]);
}

shared void exampleAlgorithmIdentifier()
{
    Byte[] buf = [#30.byte, #0d.byte, #06.byte, #09.byte, #60.byte, #86.byte, #48.byte, #01.byte, #65.byte, #03.byte, #04.byte, #02.byte, #03.byte, #05.byte, #00.byte ];
    value x = AlgorithmIdentifierDecoder<Asn1Null>(Descriptor<Asn1Null>(UniversalTag.null, nullDecoder, asn1Null()));
    value y = x.decodeGivenTag(buf, 1);
    if (is DecodingError y) {
        print(y.message);
    }
    else {
        print(y[0].asn1String);
        assert (y[1] == 15);
        assert (y[2]);
        assert (y[0].encoded == buf);
        print(hexdump(y[0].encoded));
    }
}

shared void exampleAlgorithmIdentifierWithNullDefault()
{
    Byte[] buf = [#30.byte, #0b.byte, #06.byte, #09.byte, #60.byte, #86.byte, #48.byte, #01.byte, #65.byte, #03.byte, #04.byte, #02.byte, #03.byte, #05.byte, #00.byte ];
    value x = AlgorithmIdentifierDecoder<Asn1Null>(Descriptor<Asn1Null>(UniversalTag.null, nullDecoder, asn1Null()));
    value y = x.decodeGivenTag(buf, 1);
    if (is DecodingError y) {
        print(y.message);
    }
    else {
        print(y[0].asn1String);
        assert (y[1] == 13);
        assert (!y[2]);
        assert (y[0].encoded == buf[0:13]);
        print(hexdump(y[0].encoded));
    }
}

shared void creAlgId()
{
    value x = objectIdentifier([2, 16, 840, 1, 101, 3, 4, 2, 3]);
    value y = algorithmIdentifier<Asn1Null>(x, asn1Null(Tag(11118)));
    print("encoded: " + hexdump(y.encoded));
    print(y.asn1String);
}

ObjectIdentifier pkcs1Oid = objectIdentifier([1, 2, 840, 113549, 1, 1]);
ObjectIdentifier sha256Oid = objectIdentifier([2, 16, 840, 1, 101, 3, 4, 2, 1]);

shared void creAlgIdRsaSsaPssSha256()
{
    value signatureOid = pkcs1Oid.withTrailing(10);
    
    value sha256AlgId = algorithmIdentifier(sha256Oid, asn1Null());
    
    value mgf1Oid = pkcs1Oid.withTrailing(8);
    value mgf1Sha256AlgId = algorithmIdentifier(mgf1Oid, sha256AlgId);
    
    value algId = algorithmIdentifier(signatureOid, rsaSsaParams(sha256AlgId, mgf1Sha256AlgId, 32, 1));
    
    print(algId.asn1String);
    print(hexdump(algId.encoded));
    
    value parameterDescriptor = Descriptor(nothing, RsaSsaParamsDecoder<Asn1Value<Anything>, Asn1Value<Anything>>(nothing, nothing));
    value decoder = AlgorithmIdentifierDecoder(parameterDescriptor);
}

shared class RsaSsaParams<HP1, HP2> extends Asn1Sequence<[TaggedValue<AlgorithmIdentifier<HP1>>, TaggedValue<AlgorithmIdentifier<HP2>>, TaggedValue<Asn1Integer>, TaggedValue<Asn1Integer>]>
{
    shared new (encoded, violatesDer, val) extends super.internal(encoded, violatesDer, val)
    {
        Byte[] encoded;
        Boolean violatesDer;
        [TaggedValue<AlgorithmIdentifier<HP1>>, TaggedValue<AlgorithmIdentifier<HP2>>, TaggedValue<Asn1Integer>, TaggedValue<Asn1Integer>] val;
    }
}

shared RsaSsaParams<HP1, HP2> rsaSsaParams<HP1, HP2>(AlgorithmIdentifier<HP1> hashAlgorithm, AlgorithmIdentifier<HP2> mgfAlgorithm, Integer saltLength = 20, Integer trailerField = 1)
{
    value aHashAlgorithm = taggedValue(hashAlgorithm, Tag(0));
    value aMgfAlgorithm = taggedValue(mgfAlgorithm, Tag(1));
    value aSaltLength = taggedValue(asn1Integer(saltLength), Tag(2));
    value aTrailerField = taggedValue(asn1Integer(trailerField), Tag(3));
 
    value x = encodeAsn1Sequence([aHashAlgorithm, aMgfAlgorithm, aSaltLength, aTrailerField], [asn1Null(), asn1Null(), asn1Integer(20), asn1Integer(1)]);
    assert (!is EncodingError x);
   
    return RsaSsaParams<HP1, HP2>(x, false, [aHashAlgorithm, aMgfAlgorithm, aSaltLength, aTrailerField]);
}

shared class RsaSsaParamsDecoder<HP1, HP2>(hashAlgIdDescriptor, mgfAlgIdDescriptor)
        extends SequenceDecoder<[TaggedValue<AlgorithmIdentifier<HP1>>, TaggedValue<AlgorithmIdentifier<HP2>>, TaggedValue<Asn1Integer>, TaggedValue<Asn1Integer>]>
        ([hashAlgIdDescriptor, mgfAlgIdDescriptor, Descriptor<Asn1Integer>(Tag(2), asn1IntegerDecoder), Descriptor<Asn1Integer>(Tag(3), asn1IntegerDecoder)])
        given HP1 satisfies Asn1Value<Anything>
        given HP2 satisfies Asn1Value<Anything>
{
    Descriptor<HP1> hashAlgIdDescriptor;
    Descriptor<HP2> mgfAlgIdDescriptor;
    shared actual [RsaSsaParams<HP1,HP2>, Integer, Boolean]|DecodingError decodeGivenTag(Byte[] input, Integer offset, Integer identityOctetsOffset)
    {
        return nothing;
    }
}
        

shared void xpp()
{
    value v = rsaSsaParams<Asn1Null, AlgorithmIdentifier<Asn1Null>>(algorithmIdentifier<Asn1Null>(objectIdentifier([1,2,3,4]), asn1Null()),
                                               algorithmIdentifier<AlgorithmIdentifier<Asn1Null>>(objectIdentifier([1,2,840,113549, 1, 1, 0, 1, 8]), algorithmIdentifier<Asn1Null>(objectIdentifier([1, 1, 1]), asn1Null())),
                                           20, 1);
    print(v.encoded);
    print(v.asn1String);
    
}
