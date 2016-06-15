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
    DecodingError,
    IA5String,
    IA5StringDecoder,
    ia5String,
    EncodingError
}

testExecutor(`class SpecksTestExecutor`)
class IA5StringTests()
{
    test
    shared Specification testEncodeValues() => Specification
    {
        feature {
            description="several IA5String values are encoded correctly";
            
            function when(String val, Byte[] expected)
            {
                value asn1Value = ia5String(val);
                return [asn1Value, expected];
            }
            
            examples = {
                ["", [22.byte, 0.byte]],
                ["abc", [22.byte, 3.byte, 97.byte, 98.byte, 99.byte]]
            };
            
            assertions = {
                (IA5String | EncodingError asn1Value, Byte[] expected)
                {
                    value result = assertNotEncodingError(asn1Value);
                    return expect(result.encoded, sameAs(expected));
                }
            };
        }
    };

    test
    shared Specification testDecodeValues() => Specification
    {
        feature {
            description="several IA5String values are decoded correctly";
            
            function when(Byte[] encoded, String expected)
            {
                value input = encoded.withLeading(99.byte).append([98.byte, 97.byte]);
                value decoder = IA5StringDecoder();
                value decoded = decoder.decode(input, 1);
                return [decoded, expected];
            }
            
            examples = {
                [[22.byte, 0.byte], ""],
                [[22.byte, 3.byte, 97.byte, 98.byte, 99.byte], "abc"]
            };
            
            assertions = {
                ([IA5String, Integer]|DecodingError decoded, String expected)
                {
                    value result = assertNotDecodingError(decoded);
                    return expect(result[0].val, sameAs(expected));
                },
                ([IA5String, Integer]|DecodingError decoded, String expected)
                {
                    value result = assertNotDecodingError(decoded);
                    return expect(result[0].violatesDer, sameAs(false));
                }
            };
        }
    };
}
