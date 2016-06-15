import ceylon.test {
    testExecutor,
    test
}

import com.athaydes.specks {
    Specification,
    feature,
    SpecksTestExecutor
}
import com.athaydes.specks.assertion {
    expect
}
import com.athaydes.specks.matcher {
    sameAs
}

import de.dlkw.ccrypto.asn1 {
    EncodingError,
    utcTimeFromString,
    UTCTime,
    UTCTimeDecoder,
    DecodingError
}

testExecutor(`class SpecksTestExecutor`)
class UTCTimeTests()
{
    test
    shared Specification testEncodeValues() => Specification
    {
        feature {
            description="several UTCTime values are encoded correctly";
            
            function when(String val, Byte[] expected, Boolean violatesDer)
            {
                value asn1Value = utcTimeFromString(val, 2049);
                return [asn1Value, expected, violatesDer];
            }
            
            examples = {
                ["00010100Z", [23.byte, 9.byte, 48.byte, 48.byte, 48.byte, 49.byte, 48.byte, 49.byte, 48.byte, 48.byte, 90.byte], false],
                ["49010100Z", [23.byte, 9.byte, 52.byte, 57.byte, 48.byte, 49.byte, 48.byte, 49.byte, 48.byte, 48.byte, 90.byte], false],
                ["50010100Z", [23.byte, 9.byte, 53.byte, 48.byte, 48.byte, 49.byte, 48.byte, 49.byte, 48.byte, 48.byte, 90.byte], false],
                ["00010100.10", [23.byte, 8.byte, 48.byte, 48.byte, 48.byte, 49.byte, 48.byte, 49.byte, 48.byte, 48.byte], true]
            };
            
            assertions = {
                (UTCTime | EncodingError asn1Value, Byte[] expected, Boolean violatesDer)
                {
                    value result = assertNotEncodingError(asn1Value);
                    value x = expect(result.encoded, sameAs(expected));
                    if (exists x) {
                        return x;
                    }
                    return expect(result.violatesDer, sameAs(violatesDer));
                }
            };
        }
    };
    
    value decoder = UTCTimeDecoder(2049);

    test
    shared Specification testDecodeValues() => Specification {
        feature {
            description="several UTCTime values are decoded correctly";
            
            function when(String expected, Byte[] encoded, Boolean violatesDer)
            {
                value decoded = decoder.decode(encoded);
                return [decoded, expected];
            }
            
            examples = {
                ["00010100Z", [23.byte, 9.byte, 48.byte, 48.byte, 48.byte, 49.byte, 48.byte, 49.byte, 48.byte, 48.byte, 90.byte], false],
                ["49010100Z", [23.byte, 9.byte, 52.byte, 57.byte, 48.byte, 49.byte, 48.byte, 49.byte, 48.byte, 48.byte, 90.byte], false],
                ["50010100Z", [23.byte, 9.byte, 53.byte, 48.byte, 48.byte, 49.byte, 48.byte, 49.byte, 48.byte, 48.byte, 90.byte], false],
                ["00010100.10", [23.byte, 8.byte, 48.byte, 48.byte, 48.byte, 49.byte, 48.byte, 49.byte, 48.byte, 48.byte], true]
            };
            
            assertions = {
                ([UTCTime, Integer] | DecodingError decoded, String expected)
                {
                    value result = assertNotDecodingError(decoded);
                    value x = expect(result[0].val, sameAs(expected));
                    if (exists x) {
                        return x;
                    }
                    return expect(result[0].violatesDer, sameAs(false));
                }
            };
        }
    };
}

// 00010100:00
