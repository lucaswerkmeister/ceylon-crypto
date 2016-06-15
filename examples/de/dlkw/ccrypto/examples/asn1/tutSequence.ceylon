import de.dlkw.ccrypto.asn1 {
    asn1Integer,
    octetString,
    asn1Sequence,
    Option,
    EncodingError,
    GenericSequenceDecoder,
    DecodingError,
    taggedValue,
    Tag,
    SequenceDecoder,
    Descriptor,
    Asn1Integer,
    TaggedValue,
    TaggedValueDecoder,
    hexdump,
    Asn1IntegerDecoder,
    Asn1Sequence
}

shared void tutSequence01()
{
    // encoding a sequence
    value seq = seq01();
    print(hexdump(seq.encoded));
    print(seq.asn1String);
}

Asn1Sequence<Anything> seq01()
{
    value intVal = asn1Integer(5);
    value octetStringVal = octetString([160.byte, 192.byte]);
    value seq = asn1Sequence([intVal, octetStringVal], [Option.mandatory, Option.mandatory]); // FIXME should optional be possible at all???
    if (is EncodingError seq) {
        throw AssertionError(seq.message else "");
    }
    return seq;
}

shared void tutSequence02()
{
    value seqA = seq01();
    value encoded = seqA.encoded;
    
    value res0 = GenericSequenceDecoder().decode(encoded);
    if (is DecodingError res0) {
        throw AssertionError(res0.message else "");
    }
    value [seqB, nextPos] = res0;
    print(hexdump(seqB.encoded));
    print(seqB.asn1String);
}

shared void tutSequence03()
{
    value seq = seq02();
    print(hexdump(seq.encoded));
    print(seq.asn1String);
}

Asn1Sequence<Anything> seq02()
{
    // with explicit tag
    value intVal1 = asn1Integer(7);
    value taggedIntVal = taggedValue(intVal1, Tag(88));
    value intVal2 = asn1Integer(9);
    value seq = asn1Sequence([taggedIntVal, intVal2], [Option.optional, Option.optional]);
    if (is EncodingError seq) {
        throw AssertionError(seq.message else "");
    }
    return seq;
}

Asn1Sequence<Anything> seq02b()
{
    value intVal2 = asn1Integer(9);
    value seq = asn1Sequence([null, intVal2], [Option.optional, Option.optional]);
    if (is EncodingError seq) {
        throw AssertionError(seq.message else "");
    }
    return seq;
}

shared void tutSequence04()
{
    value seqA = seq02();
    value encoded = seqA.encoded;
    
    value res0 = GenericSequenceDecoder().decode(encoded);
    if (is DecodingError res0) {
        throw AssertionError(res0.message else "");
    }
    value [seqB, nextPos] = res0;
    print(hexdump(seqB.encoded));
    print(seqB.asn1String);
}

shared void tutSequence05()
{
    value seqA = seq02();
    value encoded = seqA.encoded;
    
    value res0 = SequenceDecoder<[TaggedValue<Asn1Integer>, Asn1Integer]>([Descriptor<TaggedValue<Asn1Integer>>((_)=>TaggedValueDecoder(Tag(88), Asn1IntegerDecoder())),
        Descriptor((_)=>Asn1IntegerDecoder())]).decode(encoded);
    if (is DecodingError res0) {
        throw AssertionError(res0.message else "");
    }
    value [seqB, nextPos] = res0;
    print(hexdump(seqB.encoded));
    print(seqB.asn1String);
}

shared void tutSequence06()
{
    value seqA = seq02b();
    value encoded = seqA.encoded;
    
    value res0 = SequenceDecoder<[TaggedValue<Asn1Integer>?, Asn1Integer?]>([Descriptor<TaggedValue<Asn1Integer>>((_)=>TaggedValueDecoder(Tag(88), Asn1IntegerDecoder()), Option.optional),
        Descriptor((_)=>Asn1IntegerDecoder(), Option.optional)]).decode(encoded);
    if (is DecodingError res0) {
        throw AssertionError(res0.message else "");
    }
    value [seqB, nextPos] = res0;
    print(hexdump(seqB.encoded));
    print(seqB.asn1String);
}

shared void tutSequence07()
{
    value seqA = seq02b();
    value encoded = seqA.encoded;
    
    // FIXME default value needs no tag... take from descriptor
    value res0 = SequenceDecoder<[TaggedValue<Asn1Integer>?, Asn1Integer?]>([Descriptor<TaggedValue<Asn1Integer>>((_)=>TaggedValueDecoder(Tag(88), Asn1IntegerDecoder()), taggedValue(asn1Integer(19), Tag(88))),
        Descriptor((_)=>Asn1IntegerDecoder(), Option.optional)]).decode(encoded);
    if (is DecodingError res0) {
        throw AssertionError(res0.message else "");
    }
    value [seqB, nextPos] = res0;
    print(hexdump(seqB.encoded));
    print(seqB.asn1String);
}

