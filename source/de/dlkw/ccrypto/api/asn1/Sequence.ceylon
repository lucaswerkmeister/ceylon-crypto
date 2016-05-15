import ceylon.language.meta {
    type
}

"DEFAULT not supported"
shared class Asn1Sequence<out Types> extends Asn1Value<Types>
        given Types satisfies [GenericAsn1Value?+]
{
    shared sealed new internal(Byte[] encoded, IdentityInfo identityInfo, Integer lengthOctetsOffset, Integer contentOctetsOffset, Boolean violatesDer, Types elements)
            extends Asn1Value<Types>.direct(encoded, identityInfo, lengthOctetsOffset,  contentOctetsOffset, violatesDer, elements)
    {}
    
    shared actual String asn1ValueString => "SEQUENCE { ``" ".join(val.map((x)=>x?.asn1String else "(absent)"))`` }";
    shared actual Tag defaultTag => UniversalTag.sequence;
    shared Types elements => val;
}

// FIXME real ugly. Need to ascertain elements and defaults sequence elements are of same Asn1Value
shared [Byte[], IdentityInfo, Integer, Integer] | EncodingError encodeAsn1Sequence([Asn1Value<Anything>?+] elements, [Asn1Value<Anything> | Option +] defaults, Tag tag)
{
    value identityInfo = IdentityInfo(tag, true);
    value identityOctets = identityInfo.encoded;
    value lengthOctetsOffset = identityOctets.size;

    variable {Byte*} contentOctets = [];
    variable Integer length = 0;

    assert (elements.size == defaults.size);
    for (el in zipPairs(elements, defaults)) {
        value [element, default] = el;
        
        if (exists element) {
            value b1 = element.encoded;
            
            if (!is Option default, b1 == default.encoded) {
                // don't encode DEFAULT value
            }
            else {
                length += b1.size;
                contentOctets = contentOctets.chain(b1);
            }
        }
        else {
            if (default == Option.mandatory) {
                return EncodingError("missing (null) value is mandatory");
            }
            // don't encode DEFAULT value or leave out OPTIONAL value
        }
    }
    
    value encodedLength = encodeLength(contentOctets.size);
    return [identityOctets.chain(encodedLength).chain(contentOctets).sequence(), identityInfo, lengthOctetsOffset, lengthOctetsOffset + encodedLength.size];
}

shared Asn1Sequence<Types> | EncodingError asn1Sequence<Types>(Types elements, [Asn1Value<Anything> | Option +] defaults, Tag tag = UniversalTag.sequence)
        given Types satisfies [Asn1Value<Anything>?+]
{
    value res = encodeAsn1Sequence(elements, defaults, tag);
    if (is EncodingError res) {
        return res;
    }
    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = res;
    
    return Asn1Sequence<Types>.internal(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false, elements);
}

shared class Option of optional | mandatory
{
    shared new optional{}
    shared new mandatory{}
}

shared class Descriptor<out Element>(tag, decoder, default = Option.mandatory)
given Element satisfies GenericAsn1Value
{
    shared Tag tag;

    shared <Decoder<Element>|DecodingError>(GenericAsn1Value?[]) decoder;
    shared Element|Option default;
}

shared class GenericSequenceDecoder()
        extends Decoder<Asn1Sequence<Anything>>()
{
    shared actual [Asn1Sequence<Anything>, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer contentStart, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        variable Asn1Value<Anything>[] tmpResult = [];
        
        variable Integer startPos = contentStart;
        while (startPos < contentStart + length) {
            value res0 = decodeIdentityOctets(input, startPos);
            if (is DecodingError res0) {
                return res0;
            }
            value [l0, lengthAndContentStart, violates0] = res0;
            violatesDer ||= violates0;
            
            if (l0.tag.tagClass == TagClass.universal) {
                Decoder<Asn1Value<Anything>> decoder;
                if (l0.tag.tagNumber == UniversalTag.integer.tagNumber) {
                    decoder = asn1IntegerDecoder;
                }
                else if (l0.tag.tagNumber == UniversalTag.octetString.tagNumber) {
                    decoder = octetStringDecoder;
                }
                else {
                    return DecodingError(startPos, "unsupported tag ``l0.tag``");
                }
                value decoded = decoder.decodeGivenTag(input, lengthAndContentStart, l0, startPos, violatesDer);
                if (is DecodingError decoded) {
                    return decoded;
                }
                value decodedElement = decoded[0];
                violatesDer ||= decodedElement.violatesDer;
                
                tmpResult = tmpResult.withTrailing(decodedElement);
                startPos = decoded[1];
            }
            else {
                return DecodingError(startPos, "cannot decode sequence with tagging when no descriptors are given");
            }
        }
        if (startPos != contentStart + length) {
            return DecodingError(startPos, "SEQUENCE content is longer than described by SEQUENCE's length octet(s)");
        }
        
        "FIXME: support empty sequences"
        assert (is [Asn1Value<Anything>+] result = tmpResult); // FIXME
        value seq = Asn1Sequence<[Asn1Value<Anything>+]>.internal(input[identityOctetsOffset .. startPos - 1], identityInfo, lengthOctetsOffset, contentStart, violatesDer, result);
        return [seq, startPos];
    }
}

shared class SequenceDecoder<out Types>(els)
        extends Decoder<Asn1Sequence<Types>>()
        given Types satisfies [GenericAsn1Value?+]
{
    Descriptor<GenericAsn1Value>[] els;
    
    shared default actual [Asn1Sequence<Types>, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer contentStart, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        value defIter = els.iterator();
        
        variable GenericAsn1Value?[] tmpResult = [];
        
        variable Integer startPos = contentStart;
        while (startPos < contentStart + length) {
            value res0 = decodeIdentityOctets(input, startPos);
            if (is DecodingError res0) {
                return res0;
            }
            value [l0, lengthAndContentStart, violates0] = res0;
            violatesDer ||= violates0;
            
            variable Boolean found = false;
            while (!is Finished el = defIter.next()) {
                if (l0.tag.tagClass == el.tag.tagClass && l0.tag.tagNumber == el.tag.tagNumber) {
                    value decoder = el.decoder(tmpResult);
                    if (is DecodingError decoder) {
                        return DecodingError(lengthAndContentStart, decoder.message);
                    }
                    value decoded = decoder.decodeGivenTag(input, lengthAndContentStart, l0, startPos, violatesDer);
                    if (is DecodingError decoded) {
                        return decoded;
                    }
                    value decodedElement = decoded[0];
                    violatesDer ||= decodedElement.violatesDer;
                    
                    tmpResult = tmpResult.withTrailing(decodedElement);
                    
                    if (!is Option default = el.default) {
                        if (decodedElement.encoded == default.encoded) {
                            violatesDer = true;
                        }
                    }

                    startPos = decoded[1];
                    found = true;
                    break;
                }
                else {
                    value default = el.default;
                    if (is Option default) {
                        switch (default)
                        case (Option.mandatory) {
                            return DecodingError(startPos, "unexpected tag ``l0.tag`` in sequence, expected ``el.tag``");
                        }
                        case (Option.optional) {
                            tmpResult = tmpResult.withTrailing(null);
                        }
                    }
                    else {
                        tmpResult = tmpResult.withTrailing(default);
                    }
                }
            }
            if (!found) {
                return DecodingError(startPos, "spurious content of SEQUENCE after last element");
            }
        }
        if (startPos != contentStart + length) {
            return DecodingError(startPos, "SEQUENCE content is longer than described by SEQUENCE's length octet(s)");
        }
        while (!is Finished el = defIter.next()) {
            value default = el.default;
            if (is Option default) {
                switch (default)
                case (Option.mandatory) {
                    return DecodingError(startPos, "missing non-optional element with tag ``el.tag`` at end of SEQUENCE");
                }
                case (Option.optional) {
                    tmpResult = tmpResult.withTrailing(null);
                }
            }
            else {
                tmpResult = tmpResult.withTrailing(default);
            }
        }
        
        value result = tmpResult;
        if (!is Types result) {
            print(tmpResult);
            print(type(tmpResult));
            print(`Types`);
            throw AssertionError("Type mismatch error while sequence decoding. Check type parameters of Asn1Sequence and type parameters of the employed Decoders. Note: OPTIONAL values correspond to intersection types with ceylon.language::Null.");
        }
        value int = Asn1Sequence.internal(input[identityOctetsOffset .. startPos - 1], identityInfo, lengthOctetsOffset, contentStart, violatesDer, result);
        return [int, startPos];
    }
}
