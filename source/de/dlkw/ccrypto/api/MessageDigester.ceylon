shared interface UpdatingProcessor<out P> of P
        given P satisfies UpdatingProcessor<P>
{
    shared formal void reset();

    "Updates the internal state of this processor with a part of the message to process.
     
     Implementations of this interface should provide some sort of `finish` method to complete
     processing of a message. Call this method repeatedly to feed handy portions
     to the processor, then call that `finish` method to obtain the processed result.
     
     Returns this `UpdatingProcessor` to allow chained calls."
    shared formal P update({Byte*} message);
}

"An `UpdatingProcessor` that calculates the message digest (cryptographic hash) of a message."
shared interface MessageDigester
        satisfies UpdatingProcessor<MessageDigester>
{
    "Length of the resulting digest, in bits. This value is positive and the same for every input message."
    shared formal Integer digestLengthBits;

    "Length of the resulting digest, in octets (8 bit bytes). This value is positive and the same for every input message."    
    shared Integer digestLengthOctets => (digestLengthBits - 1) / 8 + 1;

    "Calculates and returns the message digest (hash) value from the internal state after updating it with a final message part.
     
     After the calculation, the internal state is reset so this object can be reused immediately to calculate the
     digest of another message.
     
     This is a convenience method that simply calls `finish(messagePart)`."
    shared formal Byte[] digest({Byte*} messagePart = empty);
}
