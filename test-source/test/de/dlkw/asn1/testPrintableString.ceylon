import de.dlkw.asn1 {
    printableString,
    EncodingError,
    DecodingError,
    PrintableStringDecoder
}

shared void xtrun()
{
    value x = printableString("56");
    if (is EncodingError x) {
        print(x.message);
        return;
    }
    print(x.encoded);
    print(x.asn1String);
    
    value y = PrintableStringDecoder().decode([19.byte, 1.byte, 34.byte]);
    if (is DecodingError y) {
        print(y.message);
        return;
    }
    print(y[0].encoded);
    print(y[0].asn1String);
}