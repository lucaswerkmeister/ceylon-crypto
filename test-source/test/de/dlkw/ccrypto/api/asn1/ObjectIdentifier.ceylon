import ceylon.test {
    test
}

import de.dlkw.ccrypto.api.asn1 {
    DecodingError,
    objectIdentifier,
    ObjectIdentifierDecoder
}

/*
    test
    void encodeOID()
    {
        value a = oid2(1, 2, 840, 113549, 1, 1);
        value b = ObjectIdentifier(1, 2, 840, 113549, 1, 1);
        assert (a.der == b.der);
    }*/

test
void decodeOID1()
{
    value buf = [ #06.byte, #02.byte, #92.byte, #0f.byte ];
    value r = ObjectIdentifierDecoder().decode(buf);
    if (is DecodingError r) {
        print(r.message);
        assert(false);
    }
    else {
        print(r[0].asn1String);
        print(r[0].val);
    }
}

test
void decodeOID2()
{
    value x = objectIdentifier([1, 2, 3, 400000000, 5]);
    print(x.asn1String);
    print(x.encoded);
    value y = ObjectIdentifierDecoder().decode([99.byte, 99.byte, 99.byte, 99.byte, 6.byte, 8.byte, *x.encoded], 6);
    if (is DecodingError y) {
        print(y.message);
        assert(false);
    }
    else {
        print(y[0].asn1String);
        print(y[0].encoded);
    }
}

test
void decodeOID3()
{
    value x = objectIdentifier([ for (i in 1..300) i ]);
    print(x.asn1String);
}
