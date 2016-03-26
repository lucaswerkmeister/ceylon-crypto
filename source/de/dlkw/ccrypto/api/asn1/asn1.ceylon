shared interface Asn1Value
{
    shared formal [Byte, Byte*] der;
}

shared [Byte+] encodeLength(Integer length)
{
    if (length < 128) {
        return [ length.byte ];
    }
    throw AssertionError("encoding of long form length not supported yet");
}

shared class OctetString satisfies Asn1Value
{
    shared actual [Byte, Byte, Byte*] der;
    
    shared new (Byte[] content)
    {
        value encodedLength = encodeLength(content.size);
        value rest = encodedLength.rest.chain(content);
        der = [ #04.byte, encodedLength.first, *rest ];
    }
}

shared object asn1Null satisfies Asn1Value
{
    shared actual Byte[2] der = [#05.byte, #00.byte];
}

shared class ObjectIdentifier
        satisfies Asn1Value
{
    shared actual [Byte, Byte, Byte*] der;
    
    shared new (Integer n0, Integer n1, Integer* ns)
    {
        assert (0 <= n0 <= 2);
        assert (0 <= n1 < 40);
        variable [Byte, Byte*] content = [ (40 * n0 + n1).byte ];
        for (ni in ns) {
            assert (ni >= 0);
            variable value d = ni / 128;
            variable Byte[] cc = [ (ni % 128).byte ];
            while (d > 0) {
                value rem = (d % 128).byte.or(#80.byte);
                cc = cc.withLeading(rem);
                d = d / 128;
            }
            content = content.append(cc);
        }
        value lengthAndContent = encodeLength(content.size).append(content);
        der = [ #06.byte, lengthAndContent.first, *lengthAndContent.rest ];
    }
    
    new internal([Integer, Integer, Integer*] prefix, Integer* n)
            extends ObjectIdentifier(prefix[0], prefix[1], *prefix.spanFrom(2).chain(n))
    {}
    
    shared new withPrefix(ObjectIdentifier prefix, Integer* n)
            extends ObjectIdentifier.internal(prefix.integers, *n)
    {}
    
    shared new withDer(Byte[] encoded)
    {
        // TODO use some sort of decoding exception
        assert (exists b0 = encoded[0]);
        assert (b0 == #06.byte);
        
        assert (exists b1 = encoded[1]);
        if (b1.get(7)) {
            throw AssertionError("long form length not supported");
        }
        value length = b1.unsigned;
        assert (length > 0);
        
        assert (exists b2 = encoded[2]);
        assert (b2.unsigned / 40 <= 2);
        
        value rest = encoded.spanFrom(2);
        assert (rest.size == length);
        assert (!(encoded.last?.get(7) else true));
        
        der = [b0, b1, *encoded.spanFrom(2)];
    }
    
    shared new derContent(Byte[] content)
    {
        if (true) {
            throw AssertionError("unimplemented");
        }
    }
    
    T decode<T>(T(Integer, Integer, Integer*) convert)
            given T satisfies Object
    {print("decoding, ``super.string``");
        Integer length;
        Integer contentPos;
        value length0 = der[1];
        if (length0.get(7)) {
            throw AssertionError("long form length not supported");
        }
        else {
            length = length0.unsigned;
            contentPos = 2;
        }
        assert (exists content1 = der[contentPos]?.unsigned);
        variable Integer v = 0;
        Integer? gobbleNext(Byte b)
        {
            if (b.get(7)) {
                v = v * 128 + b.and($0111_1111.byte).unsigned;
                return null;
            }
            else {
                value result = v * 128 + b.unsigned;
                v = 0;
                return result;
            }
        }
        value x = der.spanFrom(contentPos + 1).map<Integer?>(gobbleNext).coalesced;
        if (x.empty) {
            return convert(content1 / 40, content1 % 40);
        }
        else {
            return convert(content1 / 40, content1 % 40, *x);
        }
    }
    
    shared [Integer, Integer, Integer*] integers
            => decode((Integer v0, Integer v1, Integer* vn) => [v0, v1, *vn]);
    
    shared actual String string
    {
        String stringConverter(Integer v0, Integer v1, Integer* vn)
        {
            StringBuilder sb = StringBuilder();
            sb.append(v0.string).appendCharacter('.').append(v1.string);
            for (i in vn) {
                sb.appendCharacter('.').append(i.string);
            }
            return sb.string;
        }
        
        return decode<String>(stringConverter);
    }
}

"DEFAULT not yet supported"
shared class Sequence satisfies Asn1Value
{
    shared actual [Byte, Byte, Byte*] der;
    
    shared new (Asn1Value* components)
    {
        value len = components.fold(0)((n, v) => n + v.der.size);
        value encodedLength = encodeLength(len);
        value rest = encodedLength.rest.chain(components.flatMap((val) => val.der));
        der = [ #30.byte, encodedLength.first, *rest ];
    }
}
