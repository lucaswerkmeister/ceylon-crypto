"""
   This module contains support to encode and decode ASN.1 values using
   ---with some restrictions---the BER
   (*basic encoding rules*) for decoding and the DER (*distinguished encoding rules*,
   a canonical restriction of the BER)
   for encoding. If decoding detects a violation of the DER, the [[GenericAsn1Value.violatesDer]]
   flag is set on the decoded value.
   
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
