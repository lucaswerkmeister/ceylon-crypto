# Ceylon crypto

Implementation of cryptographic algorithms/mechanisms in the Ceylon language.

For a start, the SHA-256 algorithm is implemented.

## SHA-256

This is implemented in a very straightforward way from the
description of the algorithm, see [Wikipedia entry](https://en.wikipedia.org/wiki/SHA-2) or
[this document](https://web.archive.org/web/20150315061807/http://csrc.nist.gov/groups/STM/cavp/documents/shs/sha256-384-512.pdf).

Very crude tests on the JVM backend indicate that it runs at about 1/3 the speed of the standard Java implementation.

It runs using the JVM and the JavaScript runtime.

### Usage

```
import de.dlkw.ccrypto {
    createSha256
}
    
shared void run()
{
    value sha256 = createSha256();
    sha256.update({#61.byte, #62.byte});
    sha256.update({#63.byte});
    Byte[] digest = sha256.finish();
}
```

That is:

   1. Obtain an instance of the algorithm. For example,
          
       `value sha256 = createSha256();`
          
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
