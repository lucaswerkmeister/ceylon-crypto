shared class UniversalTag extends Tag
{
    new tag(Integer tagNumber) extends Tag(tagNumber, TagClass.universal){}

    shared new boolean          extends tag(1){}
    shared new integer          extends tag(2){}
    shared new bitString        extends tag(3){}
    shared new octetString      extends tag(4){}
    shared new null             extends tag(5){}
    shared new objectIdentifier extends tag(6){}
    shared new sequence         extends tag(16){}
    shared new set              extends tag(17){}
    shared new printableString  extends tag(19){}
    shared new ia5String        extends tag(22){}
    shared new utcTime          extends tag(23){}
    shared new generalizedTime  extends tag(24){}
}

shared class EncodingError(shared String? message = null)
{}

shared class EncodingMethod of primitiveDefiniteLength | constructedDefiniteLength | constructedIndefiniteLength
{
    String s;
    
    shared new primitiveDefiniteLength { s => "primitive, definite length"; }
    shared new constructedDefiniteLength { s => "constructed, definite length"; }
    shared new constructedIndefiniteLength { s => "constructed, indefinite length"; }

    shared actual String string => s;
}

shared [Byte+] encodeLength(variable Integer length)
{
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

shared String hexdigits(Byte b) => formatInteger(b.unsigned, 16).padLeading(2, '0');
shared String hexdump({Byte*} bytes) => " ".join(bytes.map((b) => hexdigits(b)));

