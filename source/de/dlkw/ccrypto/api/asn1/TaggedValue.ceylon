shared class TaggedValue<Type> extends Asn1Value<Type>
        given Type satisfies Asn1Value<Anything>
{
    Tag tag;

    shared new direct(Byte[] encoded, Tag tag, Type wrapped)
            extends super.direct(encoded, wrapped.violatesDer, wrapped)
    {
        this.tag = tag;
    }

    shared actual String asn1String => "``tag.asn1String`` EXPLICIT ``val.asn1String``";
    shared actual Type decode() => nothing;
}

shared TaggedValue<Type> taggedValue<Type>(Type wrapped, Tag tag)
        given Type satisfies Asn1Value<Anything>
{
    value encoded = IdentityInfo(tag, true).encoded.chain(encodeLength(wrapped.encoded.size)).chain(wrapped.encoded).sequence();
    return TaggedValue.direct(encoded, tag, wrapped);
}
