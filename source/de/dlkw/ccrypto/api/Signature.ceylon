shared interface Signer<in Key>
        satisfies UpdatingProcessor<Signer<Key>>
        given Key satisfies PrivateKey
{
    shared formal void init(Key key);
    
    "Calculates and returns the signature value from the internal state after updating it with a final message part.
     
     After the calculation, the internal state is reset so this object can be reused immediately to calculate the
     signature of another message.
     
     This is a convenience method that simply calls `finish(messagePart)`."
    shared formal Byte[] sign({Byte*} messagePart = empty);
}

shared interface SignatureVerifier<in Key>
        satisfies UpdatingProcessor<SignatureVerifier<Key>>
        given Key satisfies PublicKey
{
    shared formal void init(Key key);
    
    shared formal Boolean verify(Byte[] signature, {Byte*} messagePart = empty);
}