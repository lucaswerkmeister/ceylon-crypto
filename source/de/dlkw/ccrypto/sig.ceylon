/*class SHAxx256()
{


    
    void processChunk(Byte[64] chunk)
    {
        byteLength += chunk.size;
    }
 
   void processLastChunk([Byte+] chunk, Integer validBitsInLastByte = 8)
    {
        assert (!chunk.longerThan(64));
        assert (0 < validBitsInLastByte <= 8);
        
        Integer validBitsInChunk = (chunk.size - 1) * 8 + validBitsInLastByte; 
        Integer missing = 448 - validBitsInChunk;
        Integer m = missing < 0 then missing + 512 else missing;
        
        Integer bitFill = m % 8;
        Integer byteFill = m / 8;
        if (bitFill > 0) {
            Byte newLastValidByte = chunk.last.leftLogicalShift(bitFill).or(1.byte.leftLogicalShift(bitFill - 1));
            value x = {0.byte}.repeat(byteFill);
            value y = chunk.take(chunk.size - 1).chain({newLastValidByte}).chain(x).chain({0.byte, 0.byte, 0.byte, 0.byte, *toBytes(validBitsInChunk)}).sequence();
            //processChunk();
        }
    }
}
 */