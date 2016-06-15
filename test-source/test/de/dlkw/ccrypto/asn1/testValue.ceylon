import ceylon.test {
    testExecutor,
    test,
    fail
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
    GenericAsn1Value,
    GenericAsn1ValueDecoder,
    DecodingError,
    EncodingError
}

testExecutor(`class SpecksTestExecutor`)
class ValueTests()
{
    test
    shared Specification testDecodeGenericValues() => Specification
    {
        feature {
            description="several generic values are decoded correctly";
            
            function when(Byte[] identityOctets, Byte[] lengthOctets, Byte[] contentsOctets)
            {
                value innerExpected = identityOctets.append(lengthOctets).append(contentsOctets);
                value input = innerExpected.withLeading(99.byte).append([98.byte, 97.byte]);
                GenericAsn1ValueDecoder decoder = GenericAsn1ValueDecoder();
                value decoded = decoder.decode(input, 1);
                return [decoded, innerExpected, identityOctets, lengthOctets, contentsOctets];
            }
            
            examples = {
                //[[5.byte], [0.byte], []],
                [[$1001_1111.byte, 50.byte], [$1000_0000.byte, 200.byte], []]
            };
            
            assertions = {
                ([GenericAsn1Value, Integer]|DecodingError decoded, Byte[] innerExpected, Byte[] identityOctets, Byte[] lengthOctets, Byte[] contentsOctets)
                {
                    value result = assertNotDecodingError(decoded);
                    return expect(result[0].encoded, sameAs(innerExpected));
                },
                ([GenericAsn1Value, Integer]|DecodingError decoded, Byte[] innerExpected, Byte[] identityOctets, Byte[] lengthOctets, Byte[] contentsOctets)
                {
                    value result = assertNotDecodingError(decoded);
                    return expect(result[1], sameAs(1 + innerExpected.size));
                },
                ([GenericAsn1Value, Integer]|DecodingError decoded, Byte[] innerExpected, Byte[] identityOctets, Byte[] lengthOctets, Byte[] contentsOctets)
                {
                    value result = assertNotDecodingError(decoded);
                    return expect(result[0].identityOctets, sameAs(identityOctets));
                },
                ([GenericAsn1Value, Integer]|DecodingError decoded, Byte[] innerExpected, Byte[] identityOctets, Byte[] lengthOctets, Byte[] contentsOctets)
                {
                    value result = assertNotDecodingError(decoded);
                    return expect(result[0].lengthOctets, sameAs(lengthOctets));
                },
                ([GenericAsn1Value, Integer]|DecodingError decoded, Byte[] innerExpected, Byte[] identityOctets, Byte[] lengthOctets, Byte[] contentsOctets)
                {
                    value result = assertNotDecodingError(decoded);
                    return expect(result[0].identityOctets, sameAs(identityOctets));
                },
                ([GenericAsn1Value, Integer]|DecodingError decoded, Byte[] innerExpected, Byte[] identityOctets, Byte[] lengthOctets, Byte[] contentsOctets)
                {
                    value result = assertNotDecodingError(decoded);
                    return expect(result[0].violatesDer, sameAs(false));
                }
            };
        }
    };
}

[T, Integer] assertNotDecodingError<T>([T, Integer] | DecodingError probe)
        given T satisfies GenericAsn1Value
{
    if (is DecodingError probe) {
        fail((probe.message else "") + " at " + probe.offset.string);
        throw AssertionError("not reached");
    }
    return probe;
}

T assertNotEncodingError<T>(T | EncodingError probe)
        given T satisfies GenericAsn1Value
{
    if (is EncodingError probe) {
        fail(probe.message else "");
        throw AssertionError("not reached");
    }
    return probe;
}
