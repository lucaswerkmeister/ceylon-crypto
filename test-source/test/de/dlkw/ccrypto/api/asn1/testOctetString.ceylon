import ceylon.collection {
    MutableList,
    ArrayList
}
import ceylon.test {
    test,
    fail
}

import de.dlkw.ccrypto.asn1 {
    DecodingError,
    octetString,
    OctetString,
    OctetStringDecoder
}

shared class OctetStringTest()
{
    void perform(Byte[] buf, Byte[] val, Integer offset = 0)
    {
        value r = OctetStringDecoder().decode(buf, offset);
        if (is DecodingError r) {
            print(r.message);
            fail("error");
        }
        else {
            assert (!r[0].violatesDer);
            print(r[0].asn1String);
            assert (r[0].val == val);
            assert (octetString(r[0].val).encoded == buf);
        }
    }
    
    test
    shared void decodeOS0()
    {
        value buf = [ #04.byte, #01.byte, #00.byte ];
        perform(buf, [#00.byte]);
    }
    
    test
    shared void decodeOSl500()
    {
        MutableList<Byte> ls = ArrayList<Byte>();
        for (i in 499..0) {
            ls.add(i.byte);
        }
        value buf = ls.sequence();
        value buf2 = [#04.byte, #82.byte, #01.byte, 244.byte].append(buf);
        perform(buf2, buf);
        
        OctetString os = octetString(buf);
        perform(os.encoded, buf);
    }

    test
    shared void encodeOctetString1()
    {
        value expected = [ #04.byte, 0.byte ];
        value a = octetString([]);
        assert (a.encoded == expected);
    }
    
    test
    shared void encodeOctetString2()
    {
        value expected = [ #04.byte, 3.byte, 0.byte, 1.byte, 255.byte ];
        value a = octetString([0.byte, 1.byte, 255.byte]);
        assert (a.encoded == expected);
    }
}
