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
shared interface BlockProcessor
{
    shared formal Integer blockSize;
    
    shared formal void init();
    shared formal void update({Byte*} message);
    shared formal Byte[] finish();

    shared Byte[] updateFinish({Byte*} message)
    {
        update(message);
        return finish();
    }
}

abstract class AbstractBlockProcessor(blockSize)
        satisfies BlockProcessor
{
    shared actual Integer blockSize;
    
    Array<Byte> block = Array.ofSize(blockSize, Byte(0));
    
    variable Integer _numBytesUsed = 0;
    shared Integer numBytesUsed => _numBytesUsed;

//    variable Integer validBitsInLastByte = 8;
    
    shared default actual void init()
    {
        _numBytesUsed = 0;
    }

    shared actual void update({Byte*} message)
    {
        for (next in message) {
            Integer bufPos = _numBytesUsed++ % blockSize;
            block.set(bufPos, next);
            if (bufPos == blockSize - 1) {
                processBlock(block);
            }
        }
    }

    shared actual Byte[] finish()
    {
        padLast();
        value result = finishedResult;
        init();
        return result;
    }
    
    shared formal void processBlock({Byte*} block);
    shared formal void padLast();
    shared formal Byte[] finishedResult;
}
