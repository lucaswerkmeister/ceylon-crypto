import ceylon.whole {
    Whole,
    zero,
    wholeNumber,
    one
}


shared Integer calcBitLength(Whole number)
{
    if (number == zero) {
        return 0;
    }
    variable Integer len = 0;
    variable Whole n = one;
    while (n <= number) {
        len += 1;
        n = n.leftLogicalShift(1);
    }
    return len;
}

shared Whole os2ip(Byte[] msg)
{
    variable Whole num = zero;
    for (b in msg) {
        num = num.leftLogicalShift(8).or(wholeNumber(b.unsigned));
    }
    return num;
}

shared Byte[] i2osp(msg, Integer emLen)
{
    variable Whole msg;
    
    variable Byte[] output = [];
    for (i in 0:emLen) {
        value b =  msg.integer.and(#ff).byte;
        output = output.withLeading(b);
        msg = msg.rightArithmeticShift(8);
    }
    return output;
}
