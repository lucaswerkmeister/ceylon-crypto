import ceylon.test {
    test,
    fail
}
import de.dlkw.asn1 {
    asn1SetOf,
    asn1Integer,
    EncodingError,
    Tag,
    asn1Set,
    Option,
    SetOfDecoder,
    Asn1IntegerDecoder,
    DecodingError
}

test
void testSetOf01()
{
    value s1 = asn1SetOf([asn1Integer(5), asn1Integer(2), asn1Integer(7), asn1Integer(5)]);
    if (is EncodingError s1) {
        fail(s1.message);
        return;
    }
    print(s1.encoded);
    print(s1.asn1String);
    
    value s2 = SetOfDecoder(Asn1IntegerDecoder()).decode(s1.encoded.withLeading(224.byte), 1);
    if (is DecodingError s2) {
        fail(s2.message);
        return;
    }
    print(s2[0].encoded);
    print(s2[0].asn1String);
    assert (s2[1] == 15);
}

test
void testSet01()
{
    value s1 = asn1Set([asn1Integer(5, Tag(8)), asn1Integer(2), asn1Integer(7, Tag(2)), asn1Integer(5, Tag(7))], [Option.mandatory, Option.mandatory, Option.mandatory, Option.mandatory]);
    if (is EncodingError s1) {
        fail(s1.message);
        return;
    }
    print(s1.encoded);
    print(s1.asn1String);
}
