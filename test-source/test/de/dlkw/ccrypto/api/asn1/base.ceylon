import ceylon.test {
    test
}

import de.dlkw.ccrypto.api.asn1 {
    IdentityInfo,
    TagClass,
    decodeIdentityOctets,
    DecodingError,
    Tag,
    UniversalTag,
    decodeLengthOctets,
    encodeLength
}

test
void encodeTag1()
{
    value idOctets = IdentityInfo(UniversalTag.boolean, false);
    assert (idOctets.encoded == [ #01.byte ]);
}

test
void encodeTag2()
{
    value idOctets = IdentityInfo(UniversalTag.boolean, true);
    assert (idOctets.encoded == [ #21.byte ]);
}

test
void encodeTag3()
{
    value idOctets = IdentityInfo(Tag(1000, TagClass.universal), false);
    print(idOctets.encoded);
    //value x = decodeIdentityOctets(idOctets.encoded);
    //print(x);
    value y = decodeIdentityOctets([ #1f.byte, #87.byte, 104.byte ]);
    assert (!is DecodingError y);
    print(y[0].tag.tagNumber);
    assert (idOctets.encoded == [ #1f.byte, #87.byte, 104.byte ]);
}

test
void encodeTag4()
{
    value idOctets = IdentityInfo(Tag(2000, TagClass.universal), true);
    print(idOctets.encoded);
    assert (idOctets.encoded == [ #3f.byte, #8f.byte, 80.byte ]);
}

test
void encodeTag5()
{
    value idOctets = IdentityInfo(Tag(#ff_ff_ff_ff, TagClass.private), false);
    assert (idOctets.encoded == [ #df.byte, #8f.byte, #ff.byte, #ff.byte, #ff.byte, #7f.byte ]);
}

test
void decodeLengthDER0()
{
    value buf = [#00.byte];
    value r = decodeLengthOctets(buf, 0);
    assert (!is DecodingError r);
    assert (r == [0, 1, false]);
}

test
void decodeLengthBER_indefinite()
{
    value buf = [#80.byte];
    value r = decodeLengthOctets(buf, 0);
    assert (is DecodingError r);
    print(r.message);
}

test
void decodeLengthBER0_1()
{
    value buf = [#81.byte, #00.byte];
    value r = decodeLengthOctets(buf, 0);
    assert (!is DecodingError r);
    assert (r == [0, 2, true]);
}

test
void decodeLengthBER0_2()
{
    value buf = [#82.byte, #00.byte, #00.byte, #01.byte];
    value r = decodeLengthOctets(buf, 0);
    assert (!is DecodingError r);
    assert (r == [0, 3, true]);
}

test
void decodeLengthBER1()
{
    value buf = [#85.byte, #00.byte, #00.byte, #00.byte, #00.byte, #01.byte];
    value r = decodeLengthOctets(buf, 0);
    assert (!is DecodingError r);
    assert (r == [1, 6, true]);
}

test
void decodeLengthBERn()
{
    value buf = [#85.byte, #00.byte, #01.byte, #00.byte, #00.byte, #01.byte];
    value r = decodeLengthOctets(buf, 0);
    assert (!is DecodingError r);
    assert (r == [#01000001, 6, true]);
}

test
void decodeLengthDERn_1()
{
    value buf = [#84.byte, #01.byte, #00.byte, #00.byte, #01.byte];
    value r = decodeLengthOctets(buf, 0);
    assert (!is DecodingError r);
    assert (r == [#01000001, 5, false]);
}

test
void decodeLengthDERn_2()
{
    value buf = [#85.byte, #01.byte, #00.byte, #00.byte, #01.byte, #01.byte];
    value r = decodeLengthOctets(buf, 0);
    assert (is DecodingError r);
    print(r.message);
}

test
void decodeTag1()
{
    value buf= [#00.byte];
    value r = decodeIdentityOctets(buf);
    assert (!is DecodingError r);
    value [tagInfo, rest, violatesDer] = r;
    assert (tagInfo.tag.tagClass == TagClass.universal);
    assert (tagInfo.tag.tagNumber == 0);
    assert (tagInfo.constructed == false);
    assert (rest == 1);
    assert (violatesDer == false);
}

test
void decodeTag2()
{
    value buf= [#82.byte];
    value r = decodeIdentityOctets(buf);
    assert (!is DecodingError r);
    value [tagInfo, rest, violatesDer] = r;
    assert (tagInfo.tag.tagClass == TagClass.contextSpecific);
    assert (tagInfo.tag.tagNumber == 2);
    assert (tagInfo.constructed == false);
    assert (rest == 1);
    assert (violatesDer == false);
}

test
void decodeTag3()
{
    value buf= [#5e.byte];
    value r = decodeIdentityOctets(buf);
    assert (!is DecodingError r);
    value [tagInfo, rest, violatesDer] = r;
    assert (tagInfo.tag.tagClass == TagClass.application);
    assert (tagInfo.tag.tagNumber == 30);
    assert (tagInfo.constructed == false);
    assert (rest == 1);
    assert (violatesDer == false);
}

test
void decodeTag4()
{
    value buf= [#ce.byte];
    value r = decodeIdentityOctets(buf);
    assert (!is DecodingError r);
    value [tagInfo, rest, violatesDer] = r;
    assert (tagInfo.tag.tagClass == TagClass.private);
    assert (tagInfo.tag.tagNumber == 14);
    assert (tagInfo.constructed == false);
    assert (rest == 1);
    assert (violatesDer == false);
}

test
void decodeTag5()
{
    value buf= [#ee.byte, #aa.byte];
    value r = decodeIdentityOctets(buf);
    assert (!is DecodingError r);
    value [tagInfo, rest, violatesDer] = r;
    assert (tagInfo.tag.tagClass == TagClass.private);
    assert (tagInfo.tag.tagNumber == 14);
    assert (tagInfo.constructed == true);
    assert (rest == 1);
    assert (violatesDer == false);
}

test
void decodeTag6()
{
    value buf= [#9f.byte, #2a.byte];
    value r = decodeIdentityOctets(buf);
    assert (!is DecodingError r);
    value [tagInfo, rest, violatesDer] = r;
    assert (tagInfo.tag.tagClass == TagClass.contextSpecific);
    assert (tagInfo.tag.tagNumber == 42);
    assert (tagInfo.constructed == false);
    assert (rest == 2);
    assert (violatesDer == true);
}

test
void decodeTag7()
{
    value buf= [#9f.byte, #81.byte, #02.byte, #03.byte];
    value r = decodeIdentityOctets(buf);
    assert (!is DecodingError r);
    value [tagInfo, rest, violatesDer] = r;
    assert (tagInfo.tag.tagClass == TagClass.contextSpecific);
    assert (tagInfo.tag.tagNumber == 130);
    assert (tagInfo.constructed == false);
    assert (rest == 3);
    assert (violatesDer == false);
}

test
void decodeTag8()
{
    value buf= [#9f.byte, #00.byte, #02.byte, #03.byte];
    value r = decodeIdentityOctets(buf);
    assert (is DecodingError r);
    print(r.message);
}

test
void decodeTag9()
{
    value buf= [#9f.byte, #80.byte, #02.byte, #03.byte];
    value r = decodeIdentityOctets(buf);
    assert (is DecodingError r);
    print(r.message);
}

test
void encodeLength0()
{
    value x = encodeLength(0);
    assert (x == [0.byte]);
}

test
void encodeLength1()
{
    value x = encodeLength(1);
    assert (x == [1.byte]);
}

test
void encodeLength127()
{
    value x = encodeLength(127);
    assert (x == [#7f.byte]);
}

test
void encodeLength128()
{
    value x = encodeLength(128);
    assert (x == [#81.byte, #80.byte]);
}

test
void encodeLength1000()
{
    value x = encodeLength(1000);
    assert (x == [#82.byte, 3.byte, 232.byte]);
    value y = decodeLengthOctets(x, 0);
    assert (!is DecodingError y); 
    assert (y[0] == 1000);
}
