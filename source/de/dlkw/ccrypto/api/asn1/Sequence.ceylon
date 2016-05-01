import ceylon.language.meta {
    type
}

"DEFAULT not supported"
shared class Asn1Sequence<out Types> extends Asn1Value<Types>
        given Types satisfies [Asn1Value<Anything>?+]
{
    shared sealed new internal(Byte[] encoded, Boolean violatesDer, Types elements)
            extends super.direct(encoded, violatesDer, elements)
    {}
    
    shared actual String asn1String => "SEQUENCE { ``" ".join(val.map((x)=>x?.asn1String else "(absent)"))`` }";
    shared Types elements => val;
    shared actual Types decode() => nothing;
}

// FIXME real ugly. Need to ascertain elements and defaults sequence elements are of same Asn1Value
shared Byte[] | EncodingError encodeAsn1Sequence([Asn1Value<Anything>?+] elements, [Asn1Value<Anything> | Option +] defaults)
{
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
    
    value encoded = { #30.byte }.chain(encodeLength(length)).chain(contentOctets);
    return encoded.sequence();
}

shared Asn1Sequence<Types> | EncodingError asn1Sequence<Types>(Types elements, [Asn1Value<Anything> | Option +] defaults)
        given Types satisfies [Asn1Value<Anything>?+]
{
    value encoded = encodeAsn1Sequence(elements, defaults);
    if (is EncodingError encoded) {
        return encoded;
    }
    
    return Asn1Sequence<Types>.internal(encoded.sequence(), false, elements);
}

shared class Option of optional | mandatory
{
    shared new optional{}
    shared new mandatory{}
}

shared class Descriptor<out Element>(tag, decoder, default = Option.mandatory)
given Element satisfies Asn1Value<Anything>
{
    shared Tag tag;

    shared Decoder<Element> decoder;
    shared Element|Option default;
}

shared class SequenceDecoder<Types>(els)
        extends Decoder<Asn1Sequence<Types>>()
        given Types satisfies [Asn1Value<Anything>?, Asn1Value<Anything>?*]
{
    Descriptor<Asn1Value<Anything>>[] els;
    
    shared default actual [Asn1Sequence<Types>, Integer, Boolean] | DecodingError decodeGivenTag(Byte[] input, Integer offset, Integer identityOctetsOffset)
    {
        variable Boolean violatesDer = false;
        
        value res = decodeLengthOctets(input, offset);
        if (is DecodingError res) {
            return res;
        }
        value [length, contentStart, violates] = res;
        violatesDer ||= violates;

        value defIter = els.iterator();
        
        variable Asn1Value<Anything>?[] tmpResult = [];
        
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
                    value decoded = el.decoder.decodeGivenTag(input, lengthAndContentStart, startPos);
                    if (is DecodingError decoded) {
                        return decoded;
                    }
                    violatesDer ||= decoded[2];
                    
                    value decodedElement = decoded[0];
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
                            return DecodingError("unexpected tag ``l0.tag`` in sequence, expected ``el.tag``");
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
                return DecodingError("spurious content of SEQUENCE after last element");
            }
        }
        if (startPos != contentStart + length) {
            return DecodingError("SEQUENCE content is longer than described by SEQUENCE's length octet(s)");
        }
        while (!is Finished el = defIter.next()) {
            value default = el.default;
            if (is Option default) {
                switch (default)
                case (Option.mandatory) {
                    return DecodingError("missing non-optional element with tag ``el.tag`` at end of SEQUENCE");
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
        return [Asn1Sequence<Types>.internal(input[identityOctetsOffset..contentStart + length - 1], violatesDer, result), contentStart + length, violatesDer];
    }
}