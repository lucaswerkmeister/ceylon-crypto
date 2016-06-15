import ceylon.collection {
    MutableList,
    ArrayList
}
import ceylon.test {
    test,
    fail
}

import de.dlkw.asn1 {
    DecodingError,
    BitStringDecoder,
    bitStringFromBytes,
    EncodingError,
    BitString
}

shared class BitStringTest()
{
    void perform(Byte[] buf, [Byte[], Integer] expected, Integer offset = 0)
    {
        value r = BitStringDecoder().decode(buf, offset);
        if (is DecodingError r) {
            print(r.message);
            fail("error");
        }
        else {
            assert (!r[0].violatesDer);
            print(r[0].asn1String);
            value x = r[0].val;
            assert (r[0].val == expected);
            value newBitString = bitStringFromBytes(*r[0].val);
            assert (!is EncodingError newBitString);
            assert (newBitString.encoded == buf);
        }
    }
    
    test
    shared void decodeBSEmpty()
    {
        value buf = [ #03.byte, #01.byte, #00.byte ];
        perform(buf, [[], 0]);
    }
    
    test
    shared void decodeBSEmptyWrong()
    {
        value buf = [ #03.byte, #01.byte, 1.byte ];
        value res = BitStringDecoder().decode(buf);
        assert (is DecodingError res);
    }
    
    test
    shared void decodeBS0()
    {
        value buf = [ #03.byte, #02.byte, 0.byte, #00.byte ];
        perform(buf, [[#00.byte], 8]);
    }

    test
    shared void decodeBS1bitLong()
    {
        value buf = [ #03.byte, #02.byte, 7.byte, #00.byte ];
        perform(buf, [[#00.byte], 1]);
    }
    
    test
    shared void decodeBS7bitLong()
    {
        value buf = [ #03.byte, #02.byte, 1.byte, #00.byte ];
        perform(buf, [[#00.byte], 7]);
    }
    
    test
    shared void decodeBS9bitLong()
    {
        value buf = [ #03.byte, #03.byte, 7.byte, #00.byte, #00.byte ];
        perform(buf, [[#00.byte, #00.byte], 9]);
    }
    
    test
    shared void decodeOSl500()
    {
        MutableList<Byte> ls = ArrayList<Byte>();
        for (i in 499..0) {
            ls.add(i.byte);
        }
        value buf = ls.sequence();
        value buf2 = [#03.byte, #82.byte, #01.byte, 245.byte, 0.byte].append(buf);
        perform(buf2, [buf, 4000]);
        
        BitString | EncodingError os = bitStringFromBytes(buf);
        assert (!is EncodingError os);
        perform(os.encoded, [buf, 4000]);
    }

    test
    shared void encodeBitString1()
    {
        value expected = [ #03.byte, 1.byte, 0.byte ];
        value a = bitStringFromBytes([]);
        assert (!is EncodingError a);
        assert (a.encoded == expected);
    }
    
    test
    shared void encodeBitString2()
    {
        value expected = [ #03.byte, 4.byte, 0.byte, 0.byte, 1.byte, 255.byte ];
        value a = bitStringFromBytes([0.byte, 1.byte, 255.byte]);
        assert (!is EncodingError a);
        assert (a.encoded == expected);
    }
    
    test
    shared void encodeBitStringLen9()
    {
        value expected = [ #03.byte, 3.byte, 7.byte, 255.byte, 128.byte ];
        value a = bitStringFromBytes([#ff.byte, #80.byte], 9);
        assert (!is EncodingError a);
        assert (a.encoded == expected);
    }
}
