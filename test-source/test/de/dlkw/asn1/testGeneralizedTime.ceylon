import de.dlkw.asn1 {
    generalizedTimeFromInstant,
    EncodingError,
    GeneralizedTimeDecoder,
    generalizedTimeFromString,
    DecodingError
}
import ceylon.time.iso8601 {
    parseDateTime
}
import ceylon.time {
    now
}

shared void zrun()
{
    value x = generalizedTimeFromInstant(now());
    if (is EncodingError x) {
        print(x.message);
        return;
    }
    print(x.encoded);
    print(x.dateTime);
    print(x.asn1String);
    
    value y = GeneralizedTimeDecoder().decode([24.byte, 16.byte, 48.byte, 48.byte, 48.byte, 49.byte, 48.byte, 50.byte, 50.byte, 56.byte, 48.byte, 48.byte, 48.byte, 48.byte, 53.byte, 48.byte, 46.byte, 48.byte]);
    //    value y = GeneralizedTimeDecoder().decode(x.encoded);
    if (is DecodingError y) {
        print(y.message);
        return;
    }
    print(y[0].encoded);
    print(y[0].dateTime);
    print(y[0].asn1String);
    assert (!y[0].violatesDer);
    
    value z = generalizedTimeFromString("20160314001909.3");
    if (is EncodingError z) {
        print(z.message);
        return;
    }
    print(z.encoded);
    print(z.dateTime);
    print(z.asn1String);
}

shared void rrre()
{
    print(parseDateTime("20160611T123456.7")); // 2016-06-11T12:34:56.007
    print(parseDateTime("20160611T10.025")); // 2016-06-11T12:01:00.000
    print(parseDateTime("20160611T10.01")); // 2016-06-11T12:34:56.007
}
