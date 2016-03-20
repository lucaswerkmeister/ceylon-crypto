import de.dlkw.ccrypto.api {
    MessageDigester,
    UpdatingProcessor
}

"""
   Common interface for block-oriented algorithms like
   message digests or signatures.
   
   1. Obtain an instance of the algorithm. For example,
          
       ``value sha256 = createSha256();``
          
   2. Call the `update({Byte*})` method as often as you
       need, to transfer the whole message in arbitrarily
       sized parts to the algorithm.
       
   3. Obtain the resulting value---message digest (hash),
       signature value, whatever the algorithm is intended
       for---by calling `finish()`.
       
   4. You can then reuse the algorithm object for another
       message by continuing with `update` calls.
       
   Calling `update` and then `finish` can
   be combined by calling `updateFinish`.
   
   `init()` clears the message from the algorithm so that
   the next `update` will start a new message. This is normally
   not needed as a new instance will start initialized, and after calling
   `finish()` the instance will also be initialized.
"""
shared interface BlockProcessor<P> of P
        satisfies UpdatingProcessor<P>
        given P satisfies BlockProcessor<P>
{
    shared formal Integer blockSize;
    shared formal Integer? maxMessageLength;
    
    //shared formal BlockProcessor<P> init();
}

shared interface BlockProcessorDigest
        satisfies BlockProcessor<BlockProcessorDigest> & MessageDigester
{}

shared abstract class AbstractBlockProcessor<P>(blockSize) of P
        satisfies BlockProcessor<P>
        given P satisfies AbstractBlockProcessor<P>
{
    shared actual Integer blockSize;
    
    Array<Byte> block = Array.ofSize(blockSize, Byte(0));
    
    variable Integer _numBytesUsed = 0;
    shared Integer numBytesUsed => _numBytesUsed;

//    variable Integer validBitsInLastByte = 8;
    
    shared default actual AbstractBlockProcessor<P> reset()
    {
        _numBytesUsed = 0;
        return this;
    }

    shared actual P update({Byte*} messagePart)
    {
        for (next in messagePart) {
            Integer bufPos = _numBytesUsed++ % blockSize;
            block.set(bufPos, next);
            if (bufPos == blockSize - 1) {
                processBlock(block);
            }
        }
        return this of P;
    }

    shared Byte[] finish({Byte*} messagePart = empty)
    {
        update(messagePart);
        padLast();
        value result = finishedResult;
        reset();
        return result;
    }
    
    shared formal void processBlock({Byte*} block);
    shared formal void padLast();
    shared formal Byte[] finishedResult;
}

shared abstract class AbstractDigest(blockSize, digestLengthBits)
        extends AbstractBlockProcessor<AbstractDigest>(blockSize)
        satisfies MessageDigester
        //satisfies BlockProcessorDigest
{
    Integer blockSize;
    shared actual Integer digestLengthBits;
}

{Byte*} toBytes(Integer val) => {
    val.rightLogicalShift(24).byte,
    val.rightLogicalShift(16).byte,
    val.rightLogicalShift(8).byte,
    val.byte
};
