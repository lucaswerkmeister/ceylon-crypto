import de.dlkw.ccrypto.api.asn1 {
    asn1Null,
    hexdump,
    nullDecoder,
    DecodingError,
    Tag,
    genericAsn1ValueDecoder,
    taggedValue,
    TaggedValueDecoder
}

shared void tutTaggedNull01()
{
    value val = taggedValue(asn1Null(), Tag(15));
    print(hexdump(val.encoded));
    print(val.asn1String);
}

shared void tutTaggedNull02()
{
    value val = taggedValue(asn1Null(), Tag(15));
    value encoded = val.encoded;
    
    value val2 = TaggedValueDecoder(nullDecoder).decode(encoded);
    if (is DecodingError val2) {
        throw AssertionError(val2.message else "");
    }
    print(hexdump(val2[0].encoded));
    print(val2[0].asn1String);
}

shared void tutTaggedNull03()
{
    // this is hardly if ever witnessed... nonsense...? read spec.
    value val = taggedValue(asn1Null(Tag(2)), Tag(15));
    value encoded = val.encoded;
    
    value val2 = TaggedValueDecoder(nullDecoder).decode(encoded);
    if (is DecodingError val2) {
        throw AssertionError(val2.message else "");
    }
    print(hexdump(val2[0].encoded));
    print(val2[0].asn1String);
}

shared void tutTaggedNull04()
{
    value val = taggedValue(asn1Null(), Tag(15));
    value encoded = val.encoded;
    
    value val2 = genericAsn1ValueDecoder.decode(encoded);
    if (is DecodingError val2) {
        throw AssertionError(val2.message else "");
    }
    print(hexdump(val2[0].encoded));
    print(val2[0].asn1String);
}

shared void tutTaggedNull04b()
{
    value val = taggedValue(asn1Null(), Tag(15));
    value encoded = val.encoded;
    
    value val2 = TaggedValueDecoder(genericAsn1ValueDecoder).decode(encoded);
    if (is DecodingError val2) {
        throw AssertionError(val2.message else "");
    }
    print(hexdump(val2[0].encoded));
    print(val2[0].asn1String);
}
