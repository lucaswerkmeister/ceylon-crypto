import de.dlkw.asn1 {
    asn1Null,
    hexdump,
    DecodingError,
    Tag,
    asn1Integer,
    Asn1NullDecoder,
    GenericAsn1ValueDecoder,
    Asn1IntegerDecoder
}

shared void tutNull01()
{
    value val = asn1Null();
    print(hexdump(val.encoded));
    print(val.asn1String);
}

shared void tutNull02()
{
    value val = asn1Null();
    value encoded = val.encoded;
    
    value val2 = Asn1NullDecoder().decode(encoded);
    if (is DecodingError val2) {
        throw AssertionError(val2.message else "");
    }
    print(hexdump(val2[0].encoded));
    print(val2[0].asn1String);
    print(val2[0].val);
}

shared void tutNull03()
{
    value val = asn1Null(Tag(2));
    value encoded = val.encoded;
    
    value val2 = Asn1NullDecoder().decode(encoded);
    if (is DecodingError val2) {
        throw AssertionError(val2.message else "");
    }
    print(hexdump(val2[0].encoded));
    print(val2[0].asn1String);
}

shared void tutNull04()
{
    value val = asn1Null(Tag(2));
    value encoded = val.encoded;
    
    value val2 = GenericAsn1ValueDecoder().decode(encoded);
    if (is DecodingError val2) {
        throw AssertionError(val2.message else "");
    }
    print(hexdump(val2[0].encoded));
    print(val2[0].asn1String);
}

shared void tutInt01()
{
    value val = asn1Integer(88765);
    print(hexdump(val.encoded));
    print(val.asn1String);
}

shared void tutInt02()
{
    value val = asn1Integer(88765);
    value encoded = val.encoded;
    
    value val2 = Asn1IntegerDecoder().decode(encoded);
    if (is DecodingError val2) {
        throw AssertionError(val2.message else "");
    }
    print(hexdump(val2[0].encoded));
    print(val2[0].asn1String);
}

shared void tutInt03()
{
    value val = asn1Integer(88765, Tag(2));
    value encoded = val.encoded;
    
    value val2 = Asn1IntegerDecoder(Tag(2)).decode(encoded);
    if (is DecodingError val2) {
        throw AssertionError(val2.message else "");
    }
    print(hexdump(val2[0].encoded));
    print(val2[0].asn1String);
}
