import ceylon.test {
    test,
    fail
}

import de.dlkw.asn1 {
    asn1Integer,
    octetString,
    objectIdentifier,
    asn1Sequence,
    taggedValue,
    Tag,
    Option,
    EncodingError,
    Asn1Sequence,
    SequenceDecoder,
    Asn1Integer,
    Descriptor,
    DecodingError,
    hexdump,
    Asn1IntegerDecoder
}

test
void encodeSequence1()
{
    value expected = [ #30.byte, 13.byte,
        2.byte, 3.byte, 1.byte, #86.byte, #9f.byte,
        4.byte, 3.byte, 0.byte, 1.byte, 255.byte,
        6.byte, 1.byte, #2a.byte];
    value a1 = asn1Integer(99999);
    value a2 = octetString([0.byte, 1.byte, 255.byte]);
    value a3 = objectIdentifier([1, 2]);
    value aa = asn1Sequence([a1, a2, a3], [Option.mandatory, Option.mandatory, Option.mandatory]);
    assert (!is EncodingError aa);
    print(hexdump(aa.encoded));
    print(aa.asn1String);
    assert (aa.encoded == expected);
}

test
void encodeSequenceWithOptional1()
{
    value expected = [ #30.byte, 8.byte,
    2.byte, 3.byte, 1.byte, #86.byte, #9f.byte,
    6.byte, 1.byte, #2a.byte];
    value a1 = asn1Integer(99999);
    value a2 = octetString([0.byte, 1.byte, 255.byte]);
    value a3 = objectIdentifier([1, 2]);
    value aa = asn1Sequence([a1, null, a3], [Option.mandatory, Option.optional, Option.mandatory]);
    assert (!is EncodingError aa);
    print(hexdump(aa.encoded));
    print(aa.asn1String);
    assert (aa.encoded == expected);
}

test
void encodeSequenceWithDefault1a()
{
    value expected = [ #30.byte, 8.byte,
    2.byte, 3.byte, 1.byte, #86.byte, #9f.byte,
    6.byte, 1.byte, #2a.byte];
    value a1 = asn1Integer(99999);
    value a2 = octetString([0.byte, 1.byte, 255.byte]);
    value a3 = objectIdentifier([1, 2]);
    value aa = asn1Sequence([a1, a2, a3], [Option.mandatory, octetString([0.byte, 1.byte, #ff.byte]), Option.mandatory]);
    assert (!is EncodingError aa);
    print(hexdump(aa.encoded));
    print(aa.asn1String);
    assert (aa.encoded == expected);
}

test
void encodeSequenceWithDefault1b()
{
    value expected = [ #30.byte, 8.byte,
    2.byte, 3.byte, 1.byte, #86.byte, #9f.byte,
    6.byte, 1.byte, #2a.byte];
    value a1 = asn1Integer(99999);
    value a2 = octetString([0.byte, 1.byte, 254.byte]);
    value a3 = objectIdentifier([1, 2]);
    value aa = asn1Sequence([a1, a2, a3], [Option.mandatory, octetString([0.byte, 1.byte, #ff.byte]), Option.mandatory]);
    assert (!is EncodingError aa);
    print(hexdump(aa.encoded));
    print(aa.asn1String);
    assert (aa.encoded == expected);
}

test
void encodeSequenceWithDefault1c()
{
    value expected = [ #30.byte, 8.byte,
    2.byte, 3.byte, 1.byte, #86.byte, #9f.byte,
    6.byte, 1.byte, #2a.byte];
    value a1 = asn1Integer(99999);
    value a2 = octetString([0.byte, 1.byte, 254.byte]);
    value a3 = objectIdentifier([1, 2]);
    value aa = asn1Sequence([a1, null, a3], [Option.mandatory, Option.mandatory, Option.mandatory]);
    assert (is EncodingError aa);
    print(aa.message);
}

test
void encodeSequenceWithDefault1aExplicitTag()
{
    value expected = [ #30.byte, 8.byte,
    2.byte, 3.byte, 1.byte, #86.byte, #9f.byte,
    6.byte, 1.byte, #2a.byte];
    value a1 = asn1Integer(99999);
    value a2 = taggedValue(octetString([0.byte, 1.byte, 255.byte]), Tag(6));
    value a3 = objectIdentifier([1, 2]);
    value aa = asn1Sequence([a1, a2, a3], [Option.mandatory, octetString([0.byte, 1.byte, #ff.byte]), Option.mandatory]);
    assert (!is EncodingError aa);
    print(hexdump(aa.encoded));
    print(aa.asn1String);
    assert (aa.encoded == expected);
}

test
void encodeSequenceWithDefault1bExplicitTag()
{
    value expected = [ #30.byte, 8.byte,
    2.byte, 3.byte, 1.byte, #86.byte, #9f.byte,
    6.byte, 1.byte, #2a.byte];
    value a1 = asn1Integer(99999);
    value a2 = taggedValue(octetString([0.byte, 1.byte, 254.byte]), Tag(6));
    value a3 = objectIdentifier([1, 2]);
    value aa = asn1Sequence([a1, a2, a3], [Option.mandatory, octetString([0.byte, 1.byte, #ff.byte]), Option.mandatory]);
    assert (!is EncodingError aa);
    print(hexdump(aa.encoded));
    print(aa.asn1String);
    assert (aa.encoded == expected);
}

test
void decodeSeq1()
{
    value buf = [ #30.byte, #08.byte, #02.byte, #01.byte, #18.byte, #02.byte, #03.byte, #01.byte, #00.byte, #01.byte ];
    value dec = SequenceDecoder<[Asn1Integer, Asn1Integer]>([Descriptor<Asn1Integer>((_)=>Asn1IntegerDecoder()), Descriptor<Asn1Integer>((_)=>Asn1IntegerDecoder())]);
    value r = dec.decode(buf);
    if (is DecodingError r) {
        print(r.message);
        fail();
        return;
    }
    assert (r[1] == 10);
    assert (!r[0].violatesDer);
    print(r[0].asn1String);
    print(r[0].val[0].val);
    print(r[0].val[1].val);
}

test
void decodeSeq1b()
{
    value buf = [ #30.byte, #09.byte, #02.byte, #81.byte, 1.byte, #18.byte, #02.byte, #03.byte, #01.byte, #00.byte, #01.byte ];
    value dec = SequenceDecoder<[Asn1Integer, Asn1Integer]>([Descriptor<Asn1Integer>((_)=>Asn1IntegerDecoder()), Descriptor<Asn1Integer>((_)=>Asn1IntegerDecoder())]);
    value r = dec.decode(buf);
    if (is DecodingError r) {
        print(r.message);
        fail();
        return;
    }
    assert (r[1] == 11);
    assert (r[0].violatesDer);
    print(r[0].asn1String);
    print(r[0].val[0].val);
    print(r[0].val[1].val);
}

test
void decodeSeq2()
{
    value buf = [ #30.byte, #03.byte, #02.byte, #01.byte, #18.byte, #02.byte, #03.byte, #01.byte, #00.byte, #01.byte ];
    value dec = SequenceDecoder<[Asn1Integer, Asn1Integer]>([Descriptor<Asn1Integer>((_)=>Asn1IntegerDecoder()), Descriptor<Asn1Integer>((_)=>Asn1IntegerDecoder())]);
    value r = dec.decode(buf);
    assert (is DecodingError r);
    print(r.message);
}

test
void decodeSeq3()
{
    value buf = [ #30.byte, #04.byte, #02.byte, #01.byte, #18.byte, #02.byte, #03.byte, #01.byte, #00.byte, #01.byte ];
    value dec = SequenceDecoder<[Asn1Integer]>([Descriptor<Asn1Integer>((_)=>Asn1IntegerDecoder())]);
    value r = dec.decode(buf);
//    value r = decodeSequence([GenericElementDescription(TagClass2.universal, 2, TagMode.primitive, false, null, decodeAsn1Integer2GivenTag)])(buf, 0);
    assert (is DecodingError r);
    print(r.message);
}

test
void decodeSeq4()
{
    value buf = [ #30.byte, #02.byte, #02.byte, #01.byte, #18.byte, #02.byte, #03.byte, #01.byte, #00.byte, #01.byte ];
    value dec = SequenceDecoder<[Asn1Integer]>([Descriptor<Asn1Integer>((_)=>Asn1IntegerDecoder())]);
    value r = dec.decode(buf);
//    value r = decodeSequence([GenericElementDescription(TagClass2.universal, 2, TagMode.primitive, false, null, decodeAsn1Integer2GivenTag)])(buf, 0);
    assert (is DecodingError r);
    print(r.message);
}

test
void decodeSeq5()
{
    value buf = [ #30.byte, #08.byte, #02.byte, #01.byte, #18.byte, #02.byte, #03.byte, #01.byte, #00.byte, #01.byte ];
    value dec = SequenceDecoder<[Asn1Integer, Asn1Integer]>([Descriptor<Asn1Integer>((_)=>Asn1IntegerDecoder()), Descriptor<Asn1Integer>((_)=>Asn1IntegerDecoder())]);
    value r = dec.decode(buf);
//    value r = decodeSequence<[Asn1Integer2, Asn1Integer2]>([GenericElementDescription(TagClass2.universal, 2, TagMode.primitive, false, null, decodeAsn1Integer2GivenTag), GenericElementDescription(TagClass2.universal, 2, TagMode.primitive, false, null, decodeAsn1Integer2GivenTag)])(buf, 0);
    if (is DecodingError r) {
        print(r.message);
        fail();
        return;
    }
    print(r[0].asn1String);
    print(r[0].val);
}

test
void decodeSeqOpt1()
{
    // implicit tags, first optional element absent
    value buf = [ #30.byte, #03.byte, #81.byte, #01.byte, #18.byte, #82.byte, #03.byte, #01.byte, #00.byte, #01.byte ];
    value dec = SequenceDecoder<[Asn1Integer?, Asn1Integer?]>([Descriptor<Asn1Integer>((_)=>Asn1IntegerDecoder(Tag(0)), Option.optional), Descriptor<Asn1Integer>((_)=>Asn1IntegerDecoder(Tag(1)), Option.optional)]);
    value r = dec.decode(buf);
//    value r = decodeSequence<[Asn1Integer2?, Asn1Integer2]>([GenericElementDescription(TagClass2.contextSpecific, 0, TagMode.primitive, true, null, decodeAsn1Integer2GivenTag), GenericElementDescription(TagClass2.contextSpecific, 1, TagMode.primitive, false, null, decodeAsn1Integer2GivenTag)])(buf, 0);
    if (is DecodingError r) {
        print(r.message);
        assert(false);
    }
    else {
        print(r[0].asn1String);
    }
}

test
void decodeSeqOpt2()
{
    value buf = [ #30.byte, #03.byte, #80.byte, #01.byte, #18.byte, #82.byte, #03.byte, #01.byte, #00.byte, #01.byte ];
    value dec = SequenceDecoder<[Asn1Integer?, Asn1Integer?]>([Descriptor<Asn1Integer>((_)=>Asn1IntegerDecoder(Tag(0)), Option.optional), Descriptor<Asn1Integer>((_)=>Asn1IntegerDecoder(Tag(1)), Option.optional)]);
    value r = dec.decode(buf);
//    value r = decodeSequence<[Asn1Integer2, Asn1Integer2?]>([GenericElementDescription(TagClass2.contextSpecific, 0, TagMode.primitive, false, null, decodeAsn1Integer2GivenTag), GenericElementDescription(TagClass2.contextSpecific, 1, TagMode.primitive, true, null, decodeAsn1Integer2GivenTag)])(buf, 0);
    if (is DecodingError r) {
        print(r.message);
        assert(false);
    }
    else {
        print(r[0].asn1String);
    }
}

test
void decodeSeq_0()
{
    value buf = [ #30.byte, #08.byte, #80.byte, #01.byte, #18.byte, #81.byte, #03.byte, #01.byte, #00.byte, #01.byte ];
    value dec = SequenceDecoder<[Asn1Integer?, Asn1Integer?]>([Descriptor<Asn1Integer>((_)=>Asn1IntegerDecoder(Tag(0)), Option.optional), Descriptor<Asn1Integer>((_)=>Asn1IntegerDecoder(Tag(1)), Option.optional)]);
    value r = dec.decode(buf);
//    value r = decodeSequence<[Asn1Integer2, Asn1Integer2]>([GenericElementDescription(TagClass2.contextSpecific, 0, TagMode.primitive, false, null, decodeAsn1Integer2GivenTag), GenericElementDescription(TagClass2.contextSpecific, 1, TagMode.primitive, false, null, decodeAsn1Integer2GivenTag)])(buf, 0);
    if (is DecodingError r) {
        print(r.message);
        assert(false);
    }
    else {
        print(r[0].asn1String);
    }
}

test
void decodeSeqSeq()
{
    value buf = [ #30.byte, #0d.byte, #30.byte, #06.byte, #02.byte, #01.byte, #ff.byte, #02.byte, #01.byte, #01.byte, #30.byte, #03.byte, #02.byte, #01.byte, #02.byte ];
    value dec = SequenceDecoder<[Asn1Sequence<[Asn1Integer, Asn1Integer]>, Asn1Sequence<[Asn1Integer]>]>([
        Descriptor<Asn1Sequence<[Asn1Integer, Asn1Integer]>>((_)=>SequenceDecoder<[Asn1Integer, Asn1Integer]>([Descriptor<Asn1Integer>((_)=>Asn1IntegerDecoder()), Descriptor<Asn1Integer>((_)=>Asn1IntegerDecoder())])),
        Descriptor<Asn1Sequence<[Asn1Integer]>>((_)=>SequenceDecoder<[Asn1Integer]>([Descriptor<Asn1Integer>((_)=>Asn1IntegerDecoder())]))
    ]);
    value r = dec.decode(buf);
/*
    value r = decodeSequence<[Sequence2<[Asn1Integer2, Asn1Integer2]>, Sequence2<[Asn1Integer2]>]>([
        GenericElementDescription(TagClass2.universal, 16, TagMode.constructed, false, null, decodeSequenceGivenTag<
        [Asn1Integer2, Asn1Integer2]
            >([GenericElementDescription(TagClass2.universal, 2, TagMode.primitive, false, null, decodeAsn1Integer2GivenTag), GenericElementDescription(TagClass2.universal, 2, TagMode.primitive, false, null, decodeAsn1Integer2GivenTag)])),
    GenericElementDescription(TagClass2.universal, 16, TagMode.constructed, false, null, decodeSequenceGivenTag<[Asn1Integer2]>([GenericElementDescription(TagClass2.universal, 2, TagMode.primitive, false, null, decodeAsn1Integer2GivenTag)]))
    ])(buf, 0);
*/
    if (is DecodingError r) {
        print(r.message);
        assert(false);
    }
    else {
        print(r[0].asn1String);
    }
}
