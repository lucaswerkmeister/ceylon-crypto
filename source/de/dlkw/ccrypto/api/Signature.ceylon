"Calculates a cryptographic signature of a message."
by("Dirk Lattermann")
shared interface Signer
        satisfies UpdatingProcessor<Signer>
{
    "Calculates and returns the signature value from the internal state after updating it with a final message part.
     
     After the calculation, the internal state is reset so this object can be reused immediately to calculate the
     signature of another message.
     
     This is a convenience method that simply calls `finish(messagePart)`."
    shared formal Byte[] sign({Byte*} messagePart = empty);
}

"Verifies a cryptographic signature of a message."
by("Dirk Lattermann")
shared interface SignatureVerifier
        satisfies UpdatingProcessor<SignatureVerifier>
{
    "Checks if the given signature is valid for the input message.
     
     The last part of the message may be provided in the [[messagePart]] parameter. Previous parts may be provided
     by calling [[update]] before calling this method.
     
     After the verification, the internal state is reset so this object can be reused immediately to verify
     another signature."
    shared formal Boolean verify(Byte[] signature, {Byte*} messagePart = empty);
}