import de.dlkw.ccrypto.api.asn1 {
    ObjectIdentifier,
    Asn1Value,
    DecodingError,
    SequenceDecoder,
    Descriptor,
    objectIdentifierDecoder,
    UniversalTag,
    IdentityInfo,
    nullDecoder,
    Decoder,
    Asn1Null,
    asn1Null,
    hexdump,
    objectIdentifier,
    Tag,
    TaggedValue,
    Asn1Integer,
    Asn1Sequence,
    EncodingError,
    encodeAsn1Sequence,
    taggedValue,
    asn1Integer,
    asn1IntegerDecoder,
    genericAsn1ValueDecoder,
    GenericAsn1Value
}
import de.dlkw.ccrypto.api.asn1.pkcs {
    AlgorithmIdentifier,
    id_sha256,
    rsaSsaPssOid,
    algorithmIdentifier,
    mgf1Oid
}


shared class AlgorithmIdentifierDecoder<P>(Descriptor<P> parameterDescriptor)
        extends SequenceDecoder<[ObjectIdentifier, P]>(
            [Descriptor<ObjectIdentifier>(UniversalTag.objectIdentifier, (_)=>objectIdentifierDecoder), parameterDescriptor]
        )
        given P satisfies Asn1Value<Anything>
{
    shared actual [AlgorithmIdentifier<P>, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        value x = super.decodeGivenTagAndLength(input, offset, identityInfo, length, identityOctetsOffset, lengthOctetsOffset, violatesDer);
        if (is DecodingError x) {
            return x;
        }
        value [seq, nextPos] = x;
        violatesDer ||= seq.violatesDer;
        
        value erg = AlgorithmIdentifier.direct(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset, offset, violatesDer, seq.val);
        return [erg, nextPos];
    }

}

shared class AlgorithmIdentifierAnySwitch<P>()
        given P satisfies Asn1Value<Anything>
{
    ObjectIdentifier relevantObjectIdentifier(GenericAsn1Value?[] decodedElements)
    {
        assert (is ObjectIdentifier oid = decodedElements[0]);
        return oid;
    }
    
    shared Decoder<P> selectDecoder(GenericAsn1Value?[] decodedElements)
            => selectDecoderDefinedBy(relevantObjectIdentifier(decodedElements));
    
    Decoder<P> selectDecoderDefinedBy(ObjectIdentifier oid)
    {
        if (oid.encoded == id_sha256.encoded) {
            assert (is Decoder<P> nullDecoder);
            return nullDecoder;
        }
        else if (oid.encoded == rsaSsaPssOid.encoded) {
            value dec = RsaSsaParamsDecoder(Descriptor<ObjectIdentifier>(UniversalTag.objectIdentifier, (_)=>objectIdentifierDecoder),
                Descriptor<Asn1Value<Anything>>(UniversalTag.sequence, selectDecoder));
            assert (is Decoder<P> dec);
            return dec;
        }
        else {
            throw AssertionError("not a known algorithm oid: ``oid.asn1String``");
        }
    }
}









shared void exampleAlgorithmIdentifier()
{
    Byte[] buf = [#30.byte, #0d.byte, #06.byte, #09.byte, #60.byte, #86.byte, #48.byte, #01.byte, #65.byte, #03.byte, #04.byte, #02.byte, #03.byte, #05.byte, #00.byte ];
    value x = AlgorithmIdentifierDecoder<Asn1Null>(Descriptor<Asn1Null>(UniversalTag.null, (_)=>nullDecoder, asn1Null()));
    value y = x.decode(buf);
    if (is DecodingError y) {
        print(y.message);
    }
    else {
        print(y[0].asn1String);
        assert (y[1] == 15);
        assert (y[0].violatesDer);
        assert (y[0].encoded == buf);
        print(hexdump(y[0].encoded));
    }
}

shared void exampleAlgorithmIdentifierWithNullDefault()
{
    Byte[] buf = [#30.byte, #0b.byte, #06.byte, #09.byte, #60.byte, #86.byte, #48.byte, #01.byte, #65.byte, #03.byte, #04.byte, #02.byte, #03.byte, #05.byte, #00.byte ];
    value x = AlgorithmIdentifierDecoder<Asn1Null>(Descriptor<Asn1Null>(UniversalTag.null, (_)=>nullDecoder, asn1Null()));
    value y = x.decode(buf);
    if (is DecodingError y) {
        print(y.message);
    }
    else {
        print(y[0].asn1String);
        assert (y[1] == 13);
        assert (!y[0].violatesDer);
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


shared void creAlgIdRsaSsaPssSha256()
{
    value sha256AlgId = algorithmIdentifier(id_sha256, asn1Null());
    
    value mgf1Sha256AlgId = algorithmIdentifier(mgf1Oid, sha256AlgId);
    
    value algId = algorithmIdentifier(rsaSsaPssOid, rsaSsaParams(sha256AlgId, mgf1Sha256AlgId, 32, 1));
    
    print(algId.asn1String);
    print(hexdump(algId.encoded));
    
    value anySwitch = AlgorithmIdentifierAnySwitch<Asn1Value<Anything>>();
    value parameterDescriptor = Descriptor(UniversalTag.sequence, anySwitch.selectDecoder);
    value decoder = AlgorithmIdentifierDecoder(parameterDescriptor);
    
    value decoded = decoder.decode(algId.encoded);
    if (is DecodingError decoded) {
        print(decoded.message);
        throw AssertionError("");
    }
    print(decoded[0].asn1String);
}

shared class RsaSsaParams<HP1, HP2> extends Asn1Sequence<[TaggedValue<AlgorithmIdentifier<HP1>>, TaggedValue<AlgorithmIdentifier<HP2>>, TaggedValue<Asn1Integer>, TaggedValue<Asn1Integer>]>
{
    shared new (encoded, IdentityInfo identityInfo, Integer lengthOctetsOffset, Integer contentOctetsOffset, violatesDer, val)
            extends super.internal(encoded, identityInfo, lengthOctetsOffset,  contentOctetsOffset, violatesDer, val)
    {
        Byte[] encoded;
        Boolean violatesDer;
        [TaggedValue<AlgorithmIdentifier<HP1>>, TaggedValue<AlgorithmIdentifier<HP2>>, TaggedValue<Asn1Integer>, TaggedValue<Asn1Integer>] val;
    }

    shared AlgorithmIdentifier<HP1> digestAlgorithmId => val[0].val;
    shared AlgorithmIdentifier<HP2> mgfAlgorithmId => val[1].val;
    shared Integer saltLength => val[2].val.val;
}

shared RsaSsaParams<HP1, HP2> rsaSsaParams<HP1, HP2>(AlgorithmIdentifier<HP1> hashAlgorithm, AlgorithmIdentifier<HP2> mgfAlgorithm, Integer saltLength = 20, Integer trailerField = 1, Tag tag = UniversalTag.sequence)
{
    value aHashAlgorithm = taggedValue(hashAlgorithm, Tag(0));
    value aMgfAlgorithm = taggedValue(mgfAlgorithm, Tag(1));
    value aSaltLength = taggedValue(asn1Integer(saltLength), Tag(2));
    value aTrailerField = taggedValue(asn1Integer(trailerField), Tag(3));
 
    value x = encodeAsn1Sequence([aHashAlgorithm, aMgfAlgorithm, aSaltLength, aTrailerField], [asn1Null(), asn1Null(), asn1Integer(20), asn1Integer(1)], tag);
    assert (!is EncodingError x);
    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = x;
   
    return RsaSsaParams<HP1, HP2>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false, [aHashAlgorithm, aMgfAlgorithm, aSaltLength, aTrailerField]);
}

shared class RsaSsaParamsDecoder<HP1, HP2>(hashAlgIdDescriptor, mgfAlgIdDescriptor)
        extends SequenceDecoder<[TaggedValue<AlgorithmIdentifier<HP1>>, TaggedValue<AlgorithmIdentifier<HP2>>, TaggedValue<Asn1Integer>, TaggedValue<Asn1Integer>]>
        ([Descriptor<HP1>(Tag(0), hashAlgIdDescriptor.decoder), Descriptor<HP2>(Tag(1), mgfAlgIdDescriptor.decoder), Descriptor<Asn1Integer>(Tag(2), (_)=>asn1IntegerDecoder), Descriptor<Asn1Integer>(Tag(3), (_)=>asn1IntegerDecoder)])
        given HP1 satisfies Asn1Value<Anything>
        given HP2 satisfies Asn1Value<Anything>
{
    Descriptor<HP1> hashAlgIdDescriptor;
    Descriptor<HP2> mgfAlgIdDescriptor;
    shared actual [RsaSsaParams<HP1,HP2>, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer contentStart, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        value x = super.decodeGivenTagAndLength(input, contentStart, identityInfo, length, identityOctetsOffset, lengthOctetsOffset, violatesDer);
        if (is DecodingError x) {
            return x;
        }
        value [seq, nextPos] = x;
        violatesDer ||= seq.violatesDer;

        value erg = RsaSsaParams<HP1, HP2>(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset, contentStart, violatesDer, seq.val);
        return [erg, nextPos];
    }
}
        

shared void xpp()
{
    value v = rsaSsaParams<Asn1Null, AlgorithmIdentifier<Asn1Null>>(algorithmIdentifier<Asn1Null>(objectIdentifier([1,2,3,4]), asn1Null()),
                                               algorithmIdentifier<AlgorithmIdentifier<Asn1Null>>(objectIdentifier([1,2,840,113549, 1, 1, 0, 1, 8]), algorithmIdentifier<Asn1Null>(objectIdentifier([1, 1, 1]), asn1Null())),
                                           20, 1);
    print(v.encoded);
    print(v.asn1String);
    
    value sd1 = SequenceDecoder<GenericAsn1Value[4]>([Descriptor(Tag(0), (_)=>genericAsn1ValueDecoder), Descriptor(Tag(1), (_)=>genericAsn1ValueDecoder), Descriptor(Tag(2), (_)=>genericAsn1ValueDecoder), Descriptor(Tag(3), (_)=>genericAsn1ValueDecoder)]);
    if (1==1) {
        value xx = sd1.decode(v.encoded);
        if (is DecodingError xx) {
            print((xx.message else "") + " at " + xx.offset.string);
            return;
        }
        print(hexdump(xx[0].encoded));
        print(xx[0].asn1String);
        return;
    }
    
    
    
    
    
    
    value hashDecoder = AlgorithmIdentifierDecoder(Descriptor(UniversalTag.null, (_)=>nullDecoder));
    value hashDescr = Descriptor(UniversalTag.sequence, (_)=>hashDecoder);
    value mgfDecoder = AlgorithmIdentifierDecoder(Descriptor(UniversalTag.sequence, (_)=>AlgorithmIdentifierDecoder(hashDescr)));
    value pr = RsaSsaParamsDecoder(hashDescr, Descriptor(UniversalTag.sequence, (_)=>mgfDecoder));
    value xx = pr.decode(v.encoded);
    if (is DecodingError xx) {
        print((xx.message else "") + " at " + xx.offset.string);
        return;
    }
    print(xx[0].encoded);
    print(xx[0].asn1String);
    
    value ai = algorithmIdentifier(rsaSsaPssOid, v);
    print(ai.encoded);
    print(ai.asn1String);
    
    value v2 = genericAsn1ValueDecoder.decode(ai.encoded);
    assert (!is DecodingError v2);
    print(v2[0].encoded);
    print(v2[0].asn1String);

    value anySwitch = AlgorithmIdentifierAnySwitch<Asn1Value<Anything>>();
    value parameterDescriptor = Descriptor(UniversalTag.sequence, anySwitch.selectDecoder);
    value decoder = AlgorithmIdentifierDecoder(parameterDescriptor);
    value v3 = decoder.decode(ai.encoded);
    if (is DecodingError v3) {
        throw AssertionError("``v3.message else ""`` at ``v3.offset``");
    }
    print(v3[0].encoded);
    print(v3[0].asn1String);
}
