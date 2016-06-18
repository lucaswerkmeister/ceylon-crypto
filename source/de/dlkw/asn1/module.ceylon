"""
   This module contains support to encode and decode ASN.1 values.
   
   * Encoding is done using the DER (distinguished encoding rules)
   to ensure a unique encoded represenation.
   
   * Decoding is done using the BER to accept a wider range of input.
   If the data to encode is not in canonical form (that is, if it
   violates the DER, that is signalled via the [[GenericAsn1Value.violatesDer]]
   flag on the decoded object.
   
   A specific custom ASN.1 type is typically implemented using this module by implementing
   1. an [[Asn1Value]] subclass, which will be most likely a subclass of
   [[Asn1Sequence]], [[Asn1SequenceOf]] or [[Asn1SetOf]]
   2. an instance creating function taking some "basic" Ceylon types as input,
   encode them using instance creating functions of other ASN.1 types and delegating
   to the constructor of the class implemented in step 1.
   3. a [[Decoder]] subclass using the decodeSequence, decodeSequenceOf or decodeSetOf function.
"""
by("Dirk Lattermann")
module de.dlkw.asn1 "0.0.1"
{
    import ceylon.buffer "1.2.2";
    import ceylon.collection "1.2.2";
    shared import ceylon.time "1.2.2";
    shared import ceylon.whole "1.2.2";
}
