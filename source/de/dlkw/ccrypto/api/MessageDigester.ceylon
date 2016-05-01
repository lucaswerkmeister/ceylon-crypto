import de.dlkw.ccrypto.api.asn1 {
    Asn1Value,
    asn1Null,
    ObjectIdentifier
}
import de.dlkw.ccrypto.api.asn1old.pkcs {
    AlgorithmIdentifier
}

"Processes an input message in several arbitrarily sized parts, updating internal state accordingly.
 
 Typically, there is some `finish` method that optionally takes the last part of the message and calculates
 the result."
by("Dirk Lattermann")
shared interface UpdatingProcessor<out P> of P
        given P satisfies UpdatingProcessor<P>
{
    "Resets the internal state of this processor as if no message part had been submitted."
    shared formal void reset();

    "Updates the internal state of this processor with a part of the message to process.
     
     Implementations of this interface should provide some sort of `finish` method to complete
     processing of a message. Call this method repeatedly to feed handy portions
     to the processor, then call that `finish` method to obtain the processed result.
     
     Returns this `UpdatingProcessor` to allow chained calls."
    shared formal P update({Byte*} messagePart);
}

"An `UpdatingProcessor` that calculates the message digest (cryptographic hash) of a message."
by("Dirk Lattermann")
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

    "The ASN.1 object identifier describing the underlying digest algorithm of the `MessageDigester` class."
    shared formal ObjectIdentifier objectIdentifier;
    
    "The ASN.1 structure describing the algorithm parameters of this `MessageDigester` object. Defaults to NULL."
    shared default Asn1Value<Anything> parameters => asn1Null();
    
    "The ASN.1 algorithm identifier (from the PKCS #1 module) describing this `MessageDigester` object.
     
     Consists of the object identifier and the algorithm parameters."
    shared formal AlgorithmIdentifier algorithmIdentifier;
}
