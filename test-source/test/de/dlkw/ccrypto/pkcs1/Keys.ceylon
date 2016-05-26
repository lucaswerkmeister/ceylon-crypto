import ceylon.buffer {
    ByteBuffer
}
import ceylon.file {
    home
}
import ceylon.io {
    newOpenFile
}
import ceylon.whole {
    Whole,
    wholeNumber
}

import de.dlkw.ccrypto.asn1 {
    DecodingError,
    Asn1WholeDecoder,
    asn1Whole
}
import de.dlkw.ccrypto.impl {
    rsaCrtPrivateKeyImpl,
    Asn1RsaPrivateKeyDecoder
}

shared void test00()
{
    value d = Asn1WholeDecoder().decode([2.byte, 10.byte, 1.byte, 2.byte, 3.byte, 4.byte, 5.byte, 6.byte, 7.byte, 8.byte, 9.byte, 10.byte]);
    assert (!is DecodingError d);
    print(d[0].val);
    value x = asn1Whole(d[0].val);
    print(x.val);
    print(x.asn1String);
    print(x.encoded);
}
shared void test01()
{
    Whole p = wholeNumber(31);
    Whole q = wholeNumber(37);
    Whole privateExponent = wholeNumber(11);
    Whole dP = wholeNumber(3);
    Whole dQ = wholeNumber(5);
    Whole qInv = wholeNumber(13);
    value k = rsaCrtPrivateKeyImpl(wholeNumber(65537), privateExponent, p, q, dP, dQ, qInv);
    print(k.asn1String);
    print(k.encoded);
    
    value j = Asn1RsaPrivateKeyDecoder().decode(k.encoded);
    if (is DecodingError j) {
        print(j.message);
        return;
    }
    print(j[0].asn1String);
    print(j[0].encoded);
}

native shared void test02();
native("jvm") shared void test02()
{
    value p = home.childPath("privKey.der").resource;
    value f = newOpenFile(p);
    variable Byte[] a=[];
    f.readFully(void (ByteBuffer buffer)
        {
        a = buffer.sequence();
    });
    print(a.size);
    value j = Asn1RsaPrivateKeyDecoder().decode(a);
    if (is DecodingError j) {
        print(j.message);
        return;
    }
    print(j[0].asn1String);
    print(j[0].encoded);
    assert (!j[0].violatesDer);
    assert (j[1] == a.size);
}
native("js") shared void test02(){assert(false);}
