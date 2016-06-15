import ceylon.language.meta {
    type
}
import ceylon.test {
    test,
    testExecutor
}

import com.athaydes.specks {
    SpecksTestExecutor,
    feature,
    Specification
}
import com.athaydes.specks.assertion {
    expect
}
import com.athaydes.specks.matcher {
    sameAs,
    not
}

import de.dlkw.asn1 {
    Tag,
    IdentityInfo,
    decodeIdentityOctets,
    DecodingError
}

testExecutor(`class SpecksTestExecutor`)
class TagsTests()
{
    test
    shared Specification testEncodeTags() => Specification
    {
        feature {
            description="several tags are encoded correctly";
            
            function when(Integer tagNumber, Byte[] expectedEncoding) {return [tagNumber, IdentityInfo(Tag(tagNumber), false), expectedEncoding];}

            examples = {
                [0, [$1000_0000.byte]],
                [1, [$1000_0001.byte]],
                [30, [$1001_1110.byte]],
                [31, [$1001_1111.byte, $0001_1111.byte]],
                [127, [$1001_1111.byte, $0111_1111.byte]],
                [128, [$1001_1111.byte, $1000_0001.byte, $0000_0000.byte]],
                [129, [$1001_1111.byte, $1000_0001.byte, $0000_0001.byte]],
                [128 * 128 - 1, [$1001_1111.byte, $1111_1111.byte, $0111_1111.byte]],
                [$100_0000_0000_0000, [$1001_1111.byte, $1000_0001.byte, $1000_0000.byte, $0000_0000.byte]],
                [$10_0000_0000_0000_0000_0000, [$1001_1111.byte, $1000_0001.byte, $1000_0000.byte, $1000_0000.byte, $0000_0000.byte]],
                [$1111_1111_1111_1111_1111_1111_1111_1111, [$1001_1111.byte, $1000_1111.byte, $1111_1111.byte, $1111_1111.byte, $1111_1111.byte, $0111_1111.byte]],
                [$1_0000_0000_0000_0000_0000_0000_0000_0000, [$1001_1111.byte, $1001_0000.byte, $1000_0000.byte, $1000_0000.byte, $1000_0000.byte, $0000_0000.byte]]
            };
            
            assertions = {
                (Integer tagNumber, IdentityInfo identityInfo, Byte[] expectedEncoding)
                        => expect(identityInfo.encoded, sameAs(expectedEncoding))
            };
        }
    };
    
    test
    shared Specification testDecodeTags() => Specification
    {
        feature {
            description="several tags are decoded correctly";
            
            function when(Integer expectedTagNumber, Byte[] encoded)
            {
                value decoded = decodeIdentityOctets(encoded);
                return [decoded, Tag(expectedTagNumber)];
            }
            
            examples = {
                [0, [$1000_0000.byte]],
                [1, [$1000_0001.byte]],
                [30, [$1001_1110.byte]],
                [31, [$1001_1111.byte, $0001_1111.byte]],
                [127, [$1001_1111.byte, $0111_1111.byte]],
                [128, [$1001_1111.byte, $1000_0001.byte, $0000_0000.byte]],
                [129, [$1001_1111.byte, $1000_0001.byte, $0000_0001.byte]],
                [128 * 128 - 1, [$1001_1111.byte, $1111_1111.byte, $0111_1111.byte]],
                [$100_0000_0000_0000, [$1001_1111.byte, $1000_0001.byte, $1000_0000.byte, $0000_0000.byte]],
                [$10_0000_0000_0000_0000_0000, [$1001_1111.byte, $1000_0001.byte, $1000_0000.byte, $1000_0000.byte, $0000_0000.byte]],
                [$1111_1111_1111_1111_1111_1111_1111_1111, [$1001_1111.byte, $1000_1111.byte, $1111_1111.byte, $1111_1111.byte, $1111_1111.byte, $0111_1111.byte]]

                // following fails: tag number too large.
                // do we want to test this?
                //[$1_0000_0000_0000_0000_0000_0000_0000_0000, [$1001_1111.byte, $1001_0000.byte, $1000_0000.byte, $1000_0000.byte, $1000_0000.byte, $0000_0000.byte]]
            };
            
            assertions = {
                ([IdentityInfo, Integer] | DecodingError decoded, Tag expectedTag)
                {
                    value e = expect(type(decoded), not(sameAs(`DecodingError`)));
                    if (exists e) {
                        return e;
                    }
                    assert (!is DecodingError decoded);
                    Tag tag = decoded[0].tag;
                    return expect(tag, sameAs(expectedTag));
                }
            };
        }
    };

    test
    shared Specification testEncodeTagsFails() => Specification
    {
        feature {
            description="encoding invalid tags yields an error";
            
            when(Integer tagNumber, Byte[] expectedEncoding) => [tagNumber, IdentityInfo(Tag(tagNumber), false), expectedEncoding];
            
            examples = {
                // negative tag number not allowed.
                [-1, [$1000_0001.byte]]
            };
            
            assertions = {
                (Integer tagNumber, IdentityInfo identityInfo, Byte[] expectedEncoding)
                        => expect(identityInfo.encoded, sameAs(expectedEncoding))
            };
        }
    };

    test
    shared Specification testDecodeTagsFailures() => Specification
    {
        feature {
            description="decoding invalid tags yields an error";
            
            function when(Integer expectedTagNumber, Byte[] encoded)
            {
                value decoded = decodeIdentityOctets(encoded);
                return [decoded, Tag(expectedTagNumber)];
            }
            
            examples = {
                // following fails: tag number too large.
                [$1_0000_0000_0000_0000_0000_0000_0000_0000, [$1001_1111.byte, $1001_0000.byte, $1000_0000.byte, $1000_0000.byte, $1000_0000.byte, $0000_0000.byte]],
                // following fails: high-tag-number-form used for length <= 30
                [$10, [$1001_1111.byte, $0000_0010.byte]]
            };
            
            assertions = {
                ([IdentityInfo, Integer] | DecodingError decoded, Tag expectedTag)
                {
                    return expect(type(decoded), sameAs(`DecodingError`));
                }
            };
        }
    };
}
