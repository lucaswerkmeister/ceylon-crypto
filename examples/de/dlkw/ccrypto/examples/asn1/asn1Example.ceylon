import de.dlkw.ccrypto.api.asn1 {
    ObjectIdentifier,
    Asn1Value,
    DecodingError,
    SequenceDecoder,
    Descriptor,
    Decoder,
    Asn1Null,
    asn1Null,
    hexdump,
    objectIdentifier,
    Tag,
    Asn1Sequence,
    taggedValue,
    GenericAsn1Value,
    TaggedValueDecoder,
    AnySwitchRegistry,
    Option,
    Asn1NullDecoder,
    GenericAsn1ValueDecoder,
    ObjectIdentifierDecoder,
    Asn1IntegerDecoder,
    asn1Integer
}
import de.dlkw.ccrypto.api.asn1.pkcs {
    AlgorithmIdentifier,
    id_sha256,
    rsaSsaPssOid,
    algorithmIdentifier,
    mgf1Oid,
    id_sha1,
    rsaSsaParams,
    AlgorithmIdentifierDecoder,
    RsaSsaParamsDecoder,
    RsaSsaParameters
}


/*
shared class XxAlgorithmIdentifierAnySwitch<P>()
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
*/

shared class AlgorithmIdentifierAnySwitch(Map<ObjectIdentifier, Decoder<Asn1Value<Anything>>> registeredDecoders)
        extends AnySwitchRegistry(registeredDecoders)
{
    shared actual ObjectIdentifier relevantDiscriminator(GenericAsn1Value?[] decodedElements)
    {
        assert (is ObjectIdentifier oid = decodedElements[0]);
        return oid;
    }
}









shared void exampleAlgorithmIdentifier()
{
    Byte[] buf = [#30.byte, #0d.byte, #06.byte, #09.byte, #60.byte, #86.byte, #48.byte, #01.byte, #65.byte, #03.byte, #04.byte, #02.byte, #03.byte, #05.byte, #00.byte ];
    value x = AlgorithmIdentifierDecoder(Descriptor<Asn1Null>((_)=>Asn1NullDecoder(), Option.optional));
    value y = x.decode(buf);
    if (is DecodingError y) {
        print(y.message);
    }
    else {
        print(y[0].asn1String);
        assert (y[1] == 15);
        assert (!y[0].violatesDer);
        assert (y[0].encoded == buf);
        print(hexdump(y[0].encoded));
    }
}

shared void exampleAlgorithmIdentifierWithoutOptional()
{
    Byte[] buf = [#30.byte, #0b.byte, #06.byte, #09.byte, #60.byte, #86.byte, #48.byte, #01.byte, #65.byte, #03.byte, #04.byte, #02.byte, #03.byte ];
    value x = AlgorithmIdentifierDecoder(Descriptor<Asn1Null>((_)=>optionalDecoder(Asn1NullDecoder()), Option.optional));
    value y = x.decode(buf);
    if (is DecodingError y) {
        print(y.message);
    }
    else {
        print(y[0].asn1String);
        assert (y[1] == 13);
        assert (!y[0].violatesDer);
        assert (y[0].encoded == buf);
        print(hexdump(y[0].encoded));
    }
}

shared Decoder<P?> optionalDecoder<P>(Decoder<P> wrappedDecoder)
        given P satisfies Asn1Value<Anything> => wrappedDecoder;

shared void exampleAlgorithmIdentifierWithNullDefault()
{
    Byte[] buf = [#30.byte, #0b.byte, #06.byte, #09.byte, #60.byte, #86.byte, #48.byte, #01.byte, #65.byte, #03.byte, #04.byte, #02.byte, #03.byte, #05.byte, #00.byte ];
    value x = AlgorithmIdentifierDecoder(Descriptor<Asn1Null>((_)=>Asn1NullDecoder(), asn1Null()));
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
    
    value anySwitch = AlgorithmIdentifierAnySwitch(map<ObjectIdentifier, Decoder<Asn1Value<Anything>>>({id_sha256->Asn1NullDecoder()}));
    value parameterDescriptor = Descriptor(anySwitch.selectDecoder);
    value decoder = AlgorithmIdentifierDecoder(parameterDescriptor);
    
    value decoded = decoder.decode(algId.encoded, 17);
    if (is DecodingError decoded) {
        print(decoded.message);
        throw AssertionError("");
    }
    print(decoded[0].asn1String);
}




/*
shared class RsaSsaParamsDecoder<HP1, HP2>(hashAlgIdDescriptor, mgfAlgIdDescriptor)
        extends SequenceDecoder<[TaggedValue<AlgorithmIdentifier<HP1>>, TaggedValue<AlgorithmIdentifier<HP2>>, TaggedValue<Asn1Integer>, TaggedValue<Asn1Integer>]>
        ([Descriptor<TaggedValue<HP1>>(Tag(0), (y){value vv = hashAlgIdDescriptor.decoder(y);if (!is DecodingError vv) {
                return TaggedValueDecoder(vv);
            }
            return vv;}) 
    
    //hashAlgIdDescriptor.decoder)
            , Descriptor<TaggedValue<HP2>>(Tag(1), (y){value vv = mgfAlgIdDescriptor.decoder(y);if (!is DecodingError vv) {return TaggedValueDecoder(vv);}return vv;}),
             Descriptor<Asn1Integer>(Tag(2), (_)=>asn1IntegerDecoder), Descriptor<Asn1Integer>(Tag(3), (_)=>asn1IntegerDecoder)])
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
*/


        

shared void xpp()
{
    value v = rsaSsaParams<Asn1Null, AlgorithmIdentifier<Asn1Null>>(algorithmIdentifier<Asn1Null>(id_sha256, asn1Null()),
                                               algorithmIdentifier<AlgorithmIdentifier<Asn1Null>>(mgf1Oid, algorithmIdentifier<Asn1Null>(id_sha256, null)),
                                           32, 1);
    print(v.encoded);
    print(v.asn1String);
    
    if (11==1) {
        value sd1 = SequenceDecoder<GenericAsn1Value[4]>(
            [Descriptor((_)=>GenericAsn1ValueDecoder(Tag(0))),
            Descriptor((_)=>GenericAsn1ValueDecoder(Tag(1))),
            Descriptor((_)=>GenericAsn1ValueDecoder(Tag(2))),
            Descriptor((_)=>GenericAsn1ValueDecoder(Tag(3)), taggedValue(asn1Integer(1), Tag(3)))]);
        value xx = sd1.decode(v.encoded);
        if (is DecodingError xx) {
            print((xx.message else "") + " at " + xx.offset.string);
            return;
        }
        print(hexdump(xx[0].encoded));
        print(xx[0].asn1String);
    }
    
    if (11==1) {
        value sd1 = SequenceDecoder<GenericAsn1Value[4]>(
            [Descriptor((_)=>TaggedValueDecoder(Tag(0), GenericAsn1ValueDecoder())),
            Descriptor((_)=>TaggedValueDecoder(Tag(1), GenericAsn1ValueDecoder())),
            Descriptor((_)=>TaggedValueDecoder(Tag(2), GenericAsn1ValueDecoder())),
            Descriptor((_)=>TaggedValueDecoder(Tag(3), GenericAsn1ValueDecoder()), taggedValue(asn1Integer(1), Tag(3)))]);
        value xx = sd1.decode(v.encoded);
        if (is DecodingError xx) {
            print((xx.message else "") + " at " + xx.offset.string);
            return;
        }
        print(hexdump(xx[0].encoded));
        print(xx[0].asn1String);
    }
    
    if (11==1) {
        value sd1 = SequenceDecoder<GenericAsn1Value[4]>(
            [Descriptor((_)=>TaggedValueDecoder(Tag(0), SequenceDecoder<[ObjectIdentifier, Asn1Value<Anything>]>([Descriptor((_)=>ObjectIdentifierDecoder()), Descriptor((_)=>Asn1NullDecoder(), asn1Null())]))),
            Descriptor((_)=>TaggedValueDecoder(Tag(1),
                SequenceDecoder<[ObjectIdentifier, Asn1Sequence<[ObjectIdentifier, Asn1Value<Anything>]>]>(
                    [Descriptor((_)=>ObjectIdentifierDecoder()),
                     Descriptor((_)=>SequenceDecoder<[ObjectIdentifier, Asn1Value<Anything>]>(
                         [Descriptor((_)=>ObjectIdentifierDecoder()),
                          Descriptor((_)=>Asn1NullDecoder(), asn1Null())]))]))),
            Descriptor((_)=>TaggedValueDecoder(Tag(2), Asn1IntegerDecoder())),
            Descriptor((_)=>TaggedValueDecoder(Tag(3), Asn1IntegerDecoder()), taggedValue(asn1Integer(1), Tag(3)))]);
        value xx = sd1.decode(v.encoded);
        if (is DecodingError xx) {
            print((xx.message else "") + " at " + xx.offset.string);
            return;
        }
        print(hexdump(xx[0].encoded));
        print(xx[0].asn1String);
    }
    
    if (12==2) {
        value simple = algorithmIdentifier(id_sha1, asn1Null());
        value sd2 = AlgorithmIdentifierDecoder(Descriptor((_)=>Asn1NullDecoder()));
        print("CCC");
        print(simple.encoded);
        value xx = sd2.decode(simple.encoded);
        if (is DecodingError xx) {
            print((xx.message else "") + " at " + xx.offset.string);
            return;
        }
        print(xx[0].encoded);
        print(xx[0].asn1String);
    }
    
    if (21==2) {
        value x=[48.byte, 9.byte, 6.byte, 5.byte, 43.byte, 14.byte, 3.byte, 2.byte, 26.byte, 5.byte, 0.byte];
        value sw = AlgorithmIdentifierAnySwitch(map({id_sha1->Asn1NullDecoder()}));
        value sd2 = AlgorithmIdentifierDecoder(Descriptor(sw.selectDecoder));
        value xx = sd2.decode(x);
        if (is DecodingError xx) {
            print((xx.message else "") + " at " + xx.offset.string);
            return;
        }
        print(xx[0].encoded);
        print(xx[0].asn1String);
    }
    
    if (3==3) {
        value hashSw = AlgorithmIdentifierAnySwitch(map({id_sha1->Asn1NullDecoder(), id_sha256->Asn1NullDecoder()}));
        /*
        function aaa(GenericAsn1Value?[] gav)
        {
            value vv = hashSw.selectDecoder(gav);
            if (!is DecodingError vv) {
                return TaggedValueDecoder(vv);
            }
            return vv;
        }
         */
        
        value hashAlgIdDecoder = AlgorithmIdentifierDecoder(Descriptor(hashSw.selectDecoder));
        value hashAlgDescriptor = Descriptor((_)=>hashAlgIdDecoder);
        
        value test1 = hashAlgDescriptor.decoder([]);
        
        value mgfSw = AlgorithmIdentifierAnySwitch(map({mgf1Oid->AlgorithmIdentifierDecoder(Descriptor(hashSw.selectDecoder))}));
        value mgfAlgIdDecoder = AlgorithmIdentifierDecoder(Descriptor(mgfSw.selectDecoder));
        value mgfAlgDescriptor = Descriptor((_)=>mgfAlgIdDecoder);
//        value sw = AlgorithmIdentifierAnySwitch(map({rsaSsaPssOid->RsaSsaParamsDecoder(Descriptor(Tag(0), (y){value vv = hashSw.selectDecoder(y);if (!is DecodingError vv) {
//                return TaggedValueDecoder(vv);
//            }
//            return vv;}),
//            Descriptor(Tag(1), mgfSw.selectDecoder))}));

// here, the type inferral does not yield the desired result:
// we need RsaSsaParamsDecoder<Asn1Value<Anything>, out Asn1Value<Anything>>,
// not RsaSsaParamsDecoder<AlgorithmIdentifier<Asn1Value<Anything>>, AlgorithmIdentifier<Asn1Value<Anything>>>!
            value sw = AlgorithmIdentifierAnySwitch(map({rsaSsaPssOid->RsaSsaParamsDecoder<Asn1Value<Anything>, Asn1Value<Anything>>(hashAlgDescriptor,
            mgfAlgDescriptor)}));
        value sd2 = AlgorithmIdentifierDecoder(Descriptor(sw.selectDecoder, asn1Null()));
        value vv = algorithmIdentifier(rsaSsaPssOid, v);
        print(vv.encoded);
        print(vv.asn1String);
        value xx = sd2.decode(vv.encoded);
        if (is DecodingError xx) {
            print((xx.message else "") + " at " + xx.offset.string);
            return;
        }
        value [sigAlgId, nextPos] = xx;
        
        if (sigAlgId.objectIdentifier == rsaSsaPssOid) {
            print("using RSASSA-PSS signature");
            assert (is RsaSsaParameters<Asn1Value<Anything>, Asn1Value<Anything>> params = sigAlgId.parameters);
            if (params.digestAlgorithmId.objectIdentifier == id_sha1) {
                print("using SHA-1 as digest");
            }
            else if (params.digestAlgorithmId.objectIdentifier == id_sha256) {
                print("using SHA-256 as digest");
            }
            
            if (params.mgfAlgorithmId.objectIdentifier == mgf1Oid) {
                assert (is AlgorithmIdentifier<> mgf1Hash = params.mgfAlgorithmId.parameters); 
                if (mgf1Hash.objectIdentifier == id_sha1) {
                    print("using SHA-1 as digest in MGF1");
                }
                else if (mgf1Hash.objectIdentifier == id_sha256) {
                    print("using SHA-256 as digest in MGF1");
                }
            }
            else {
                throw AssertionError("unsupported mask generating function ``params.mgfAlgorithmId.objectIdentifier``.");
            }
            print("salt length ``params.saltLength``");
        }
        else {
            throw AssertionError("unsupported signature algorithm ``sigAlgId.objectIdentifier``");
        }
        
        print(xx[0].encoded);
        print(xx[0].asn1String);
    }
    
    
    
    print("XY");
    value hashDecoder = AlgorithmIdentifierDecoder(Descriptor((_)=>Asn1NullDecoder()));
    value hashDescr = Descriptor((_)=>hashDecoder);
    value mgfDecoder = AlgorithmIdentifierDecoder(Descriptor((_)=>AlgorithmIdentifierDecoder(hashDescr)));
    value pr = RsaSsaParamsDecoder<Asn1Value<Anything>, Asn1Value<Anything>>(hashDescr, Descriptor((_)=>mgfDecoder));
    
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
    
    value v2 = GenericAsn1ValueDecoder().decode(ai.encoded);
    assert (!is DecodingError v2);
    print(v2[0].encoded);
    print(v2[0].asn1String);

    value anySwitch = AlgorithmIdentifierAnySwitch(map({rsaSsaPssOid->pr}));
    value parameterDescriptor = Descriptor(anySwitch.selectDecoder);
    value decoder = AlgorithmIdentifierDecoder(parameterDescriptor);
    value v3 = decoder.decode(ai.encoded);
    if (is DecodingError v3) {
        throw AssertionError("``v3.message else ""`` at ``v3.offset``");
    }
    print(v3[0].encoded);
    print(v3[0].asn1String);
}

shared void rr()
{
    value x = algorithmIdentifier<Asn1Null>(objectIdentifier([1, 2, 3]), asn1Null());
    value xx = taggedValue(x, Tag(6));
    value vv = xx.encoded;
    
    value d = AlgorithmIdentifierDecoder(Descriptor((_)=>Asn1NullDecoder(), asn1Null()));
    value dd = TaggedValueDecoder<AlgorithmIdentifier<>>(Tag(6), d);
    
    value z = d.decode(x.encoded);
    
    value zz = dd.decode(vv);
    if (is DecodingError zz) {
        print(zz.message);
        return;
    }
    print(zz[0].asn1String);
}
