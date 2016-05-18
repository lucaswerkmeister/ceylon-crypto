shared class GenericAsn1Value(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer)
{
    shared Byte[] encoded;
    shared IdentityInfo identityInfo;
    shared Integer lengthOctetsOffset;
    shared Integer contentOctetsOffset;
    
    shared Boolean violatesDer;
    
    shared Byte[] identityOctets => encoded[...lengthOctetsOffset];
    shared Byte[] lengthOctets => encoded[lengthOctetsOffset .. contentOctetsOffset - 1];
    shared Byte[] contentOctets => encoded[contentOctetsOffset...];
    
    shared default String asn1String => "``identityInfo.tag.asn1String`` ``asn1ValueString``";
    shared default String asn1ValueString => "generic contents ``hexdump(contentOctets)``";
}

shared class GenericAsn1ValueDecoder(Tag? tag = null)
        extends Decoder<GenericAsn1Value>(tag)
{
    shared actual [GenericAsn1Value, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, Boolean violatesDer)
    {
        Integer nextPos = offset + length;
        value valu = GenericAsn1Value(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset - identityOctetsOffset, offset - identityOctetsOffset, violatesDer);
        return [valu, nextPos];
    }
}

shared abstract class Asn1Value<out Value>
        extends GenericAsn1Value
{
    Value? storedValue;
    
    shared new direct(Byte[] encoded, IdentityInfo identityInfo, Integer lengthOctetsOffset, Integer contentOctetsOffset, Boolean violatesDer, Value? val = null)
            extends GenericAsn1Value(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer)
    {
        this.storedValue = val;
    }
    /*
    shared new decoding(Byte[] encoded, Boolean violatesDer)
    {
        this.encoded = encoded;
        this.violatesDer = violatesDer;
        
        this.storedValue = null;
    }
     */

    shared default Value decode(){
        // this error is thrown in subclass that need to implement it and don't.
        throw AssertionError("decode() needs to be implemented in subclasses that don't store a decoded value!");
    }
    shared Value val => storedValue else decode();
    
    shared formal Tag defaultTag;
    shared default actual String asn1String
    {
        if (identityInfo.tag == defaultTag) {
            return asn1ValueString;
        }
        else {
            return "``identityInfo.tag.asn1String`` IMPLICIT ``asn1ValueString``";
        }
    }
}
