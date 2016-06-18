"Enum class for the (supported) tags in tag class UNIVERSAL."
shared class UniversalTag extends Tag
{
    new tag(Integer tagNumber) extends Tag(tagNumber, TagClass.universal){}

    "Standard tag for BOOLEAN, tag number 1"
    shared new boolean          extends tag(1){}
    "Standard tag for INTEGER, tag number 2"
    shared new integer          extends tag(2){}
    "Standard tag for BIT STRING, tag number 3"
    shared new bitString        extends tag(3){}
    "Standard tag for OCTET STRING, tag number 4"
    shared new octetString      extends tag(4){}
    "Standard tag for NULL, tag number 5"
    shared new null             extends tag(5){}
    "Standard tag for OBJECT IDENTIFIER, tag number 6"
    shared new objectIdentifier extends tag(6){}
    "Standard tag for UTF8String, tag number 12"
    shared new utf8String       extends tag(12){}
    "Standard tag for SEQUENCE and SEQUENCE OF, tag number 16"
    shared new sequence         extends tag(16){}
    "Standard tag for SET and SET OF, tag number 17"
    shared new set              extends tag(17){}
    "Standard tag for PrintableString, tag number 19"
    shared new printableString  extends tag(19){}
    "Standard tag for IA5String, tag number 22"
    shared new ia5String        extends tag(22){}
    "Standard tag for UTCTime, tag number 23"
    shared new utcTime          extends tag(23){}
    "Standard tag for GeneralizedTime, tag number 24"
    shared new generalizedTime  extends tag(24){}
}

shared class EncodingError(shared String? message = null)
{}

"Enum class for the length encoding methods."
shared class EncodingMethod of primitiveDefiniteLength | constructedDefiniteLength | constructedIndefiniteLength
{
    String s;
    ""
    shared new primitiveDefiniteLength { s => "primitive, definite length"; }
    ""
    shared new constructedDefiniteLength { s => "constructed, definite length"; }
    "not supported"
    shared new constructedIndefiniteLength { s => "constructed, indefinite length"; }

    shared actual String string => s;
}

"Encodes the length octets."
shared [Byte+] encodeLength(length)
{
    "The length to encode."
    variable Integer length;
    
    assert (length >= 0);
    if (length < 128) {
        return [ length.byte ];
    }
    
    variable Byte[] encodedLength = [];
    while (length > 0) {
        encodedLength = encodedLength.withLeading(length.byte);
        length /= 256;
    }
    // no worries for length being longer than 127  
    return encodedLength.withLeading(encodedLength.size.byte.or($1000_0000.byte));
}

"Formats a Byte as a two-digit hexadecimal number."
shared String hexdigits(Byte b) => formatInteger(b.unsigned, 16).padLeading(2, '0');
"Format a Byte sequence as a sequence of two-digit hexadecimal numbers, separated by a space."
shared String hexdump({Byte*} bytes) => " ".join(bytes.map((b) => hexdigits(b)));

