import ceylon.test {
    test
}

import de.dlkw.ccrypto.asn1 {
    asn1Integer,
    Tag,
    TagClass,
    taggedValue
}
import de.dlkw.ccrypto.api.asn1old {
    hexdump
}

test
void testTaggedValue()
{
    value v1 = asn1Integer(15);
    value tagged = taggedValue(v1, Tag(3));
    print(hexdump(tagged.encoded));
    print(tagged.asn1String);
    assert (tagged.encoded == [ #a3.byte, 3.byte, #02.byte, 1.byte, 15.byte]);
}