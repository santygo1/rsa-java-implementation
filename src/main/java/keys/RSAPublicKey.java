package keys;

import java.math.BigInteger;

public record RSAPublicKey(BigInteger publicExponent, BigInteger modulus){ }
