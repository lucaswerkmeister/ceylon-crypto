

shared class Asn1Set<Types>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Value<Types>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        given Types satisfies [Asn1Value<Anything>?+]
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    Types elements;

    shared actual String asn1ValueString => "SET { ``" ".join(val.map((x)=>x?.asn1String else "(absent)"))`` }";
    shared actual Tag defaultTag => UniversalTag.set;
}

shared class Asn1SetOf<Inner>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Value<Inner[]>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        given Inner satisfies Asn1Value<Anything>
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    Inner[] elements;

    shared actual String asn1ValueString => "SET OF { ``" ".join(val.map((x)=>x.asn1String))`` }";
    shared actual Tag defaultTag => UniversalTag.set;
}

shared class Asn1Sequ<out Types>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Value<Types>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        given Types satisfies [GenericAsn1Value?+]
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    Types elements;

    shared actual String asn1ValueString => "SEQUENCE { ``" ".join(val.map((x)=>x?.asn1String else "(absent)"))`` }";
    shared actual Tag defaultTag => UniversalTag.sequence;
}

shared class Asn1SequenceOf<Inner>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Value<Inner[]>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        given Inner satisfies Asn1Value<Anything>
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    Inner[] elements;

    shared actual String asn1ValueString => "SEQUENCE OF { ``" ".join(val.map((x)=>x.asn1String))`` }";
    shared actual Tag defaultTag => UniversalTag.sequence;
}

Comparison compareTags(Tag x, Tag y)
{
    value c = x.tagClass.highBits.unsigned <=> y.tagClass.highBits.unsigned;
    if (c != equal) {
        return c;
    }
    return x.tagNumber <=> y.tagNumber;
}

Comparison compareEncoded(Asn1Value<Anything> x, Asn1Value<Anything> y)
{
    Byte[] bx = x.encoded;
    Byte[] by = y.encoded;
    
    value [gx, gy, swap] = if (bx.size <= by.size) then [bx, by, false] else [by, bx, true];
    
    value ix = gx.iterator();
    value iy = gy.iterator();
    while (!is Finished elx = ix.next()) {
        value ely = iy.next();
        assert (!is Finished ely);
        
        value cmp = elx.unsigned <=> ely.unsigned;
        if (cmp != equal) {
            return if (swap) then cmp.reversed else cmp;
        }
    }
    value ely = iy.next();
    if (is Finished ely) {
        return equal;
    }
    return if (swap) then larger else smaller;
}

shared Asn1SequenceOf<Inner> asn1SequenceOf<Inner>(Inner[] elements, Tag tag = UniversalTag.sequence)
        given Inner satisfies Asn1Value<Anything>
{
    value en = encodeAsn1Sequence(elements, elements.collect((_) => Option.mandatory), tag);
    assert (!is EncodingError en);

    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = en;
    return Asn1SequenceOf<Inner>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false, elements);
}

"""
   Using different tags on the elements might not make sense in ASN.1. I don't know now.
   The attribute [[val]] will return the elements in the order of the DER encoding.
"""
shared Asn1SetOf<Inner> | EncodingError asn1SetOf<Inner>(Inner[] elements, Tag tag = UniversalTag.set)
        given Inner satisfies Asn1Value<Anything>
{
    value sorted = elements.sort(compareEncoded);

    value en = encodeAsn1Sequence(sorted, sorted.collect((_) => Option.mandatory), tag);
    if (is EncodingError en) {
        return en;
    }
    
    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = en;
    return Asn1SetOf<Inner>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false, sorted);
}

"""
   The attribute [[val]] will return the elements in the order given in the [[elements]] parameter here,
   *not* in the order of the DER encoding!
"""
shared Asn1Set<Types> | EncodingError asn1Set<Types>(Types elements, [Asn1Value<Anything> | Option +] defaults, Tag tag = UniversalTag.set)
        given Types satisfies [Asn1Value<Anything>+]
{
    // sort the contents to respect the DER.
    // the sorted elements won't conform to the Types tuple.
    value sorted = elements.sort((x, y) => compareTags(x.tag, y.tag));

    value en = encodeAsn1Sequence(sorted, defaults, tag);
    if (is EncodingError en) {
        return en;
    }

    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = en;
    return Asn1Set<Types>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false, elements);
}

shared class SequenceOfDecoder<Inner>(innerDecoder, Tag tag = UniversalTag.sequence)
        extends Decoder<Asn1SequenceOf<Inner>>(tag)
        given Inner satisfies Asn1Value<Anything>
{
    Decoder<Inner> innerDecoder;
    
    shared default actual [Asn1SequenceOf<Inner>, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer contentStart, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        variable Inner[] tmpResult = [];
        
        variable Integer startPos = contentStart;
        while (startPos < contentStart + length) {
            value res0 = decodeIdentityOctets(input, startPos);
            if (is DecodingError res0) {
                return res0;
            }
            value [l0, lengthAndContentStart, violates0] = res0;
            violatesDer ||= violates0;
            
            assert (exists expectedTag = innerDecoder.tag);
            if (l0.tag == expectedTag) {
                value decoded = innerDecoder.decodeGivenTag(input, lengthAndContentStart, l0, startPos, violatesDer);
                if (is DecodingError decoded) {
                    return decoded;
                }
                value decodedElement = decoded[0];
                violatesDer ||= decodedElement.violatesDer;
                
                tmpResult = tmpResult.withTrailing(decodedElement);

                startPos = decoded[1];
            }
            else {
                return DecodingError(startPos, "tags of elements in SEQUENCE OF differ");
            }
        }
        if (startPos != contentStart + length) {
            return DecodingError(startPos, "SEQUENCE OF content is longer than described by SEQUENCE OF's length octet(s)");
        }

        value int = Asn1SequenceOf(input[identityOctetsOffset .. startPos - 1], identityInfo, lengthOctetsOffset - identityOctetsOffset, contentStart - identityOctetsOffset, violatesDer, tmpResult);
        return [int, startPos];
    }
}

shared class SetOfDecoder<Inner>(innerDecoder, Tag tag = UniversalTag.set)
        extends Decoder<Asn1SetOf<Inner>>(tag)
        given Inner satisfies Asn1Value<Anything>
{
    Decoder<Inner> innerDecoder;
    
    shared default actual [Asn1SetOf<Inner>, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer contentStart, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        variable Inner[] tmpResult = [];
        variable Inner? previousElement = null;
        
        variable Integer startPos = contentStart;
        while (startPos < contentStart + length) {
            value res0 = decodeIdentityOctets(input, startPos);
            if (is DecodingError res0) {
                return res0;
            }
            value [l0, lengthAndContentStart, violates0] = res0;
            violatesDer ||= violates0;
            
            assert (exists expectedTag = innerDecoder.tag);
            if (l0.tag == expectedTag) {
                value decoded = innerDecoder.decodeGivenTag(input, lengthAndContentStart, l0, startPos, violatesDer);
                if (is DecodingError decoded) {
                    return decoded;
                }
                value decodedElement = decoded[0];
                violatesDer ||= decodedElement.violatesDer;
                
                if (exists p = previousElement) {
                    if (compareEncoded(p, decodedElement) != smaller) {
                        violatesDer = true;
                    }
                }
                
                tmpResult = tmpResult.withTrailing(decodedElement);
                
                startPos = decoded[1];
            }
            else {
                return DecodingError(startPos, "tags of elements in SET OF differ");
            }
        }
        if (startPos != contentStart + length) {
            return DecodingError(startPos, "SET OF content is longer than described by SET OF's length octet(s)");
        }
        
        value int = Asn1SetOf(input[identityOctetsOffset .. startPos - 1], identityInfo, lengthOctetsOffset - identityOctetsOffset, contentStart - identityOctetsOffset, violatesDer, tmpResult);
        return [int, startPos];
    }
}
