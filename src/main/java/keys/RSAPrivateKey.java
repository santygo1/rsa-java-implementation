package keys;

import java.math.BigInteger;

public record RSAPrivateKey(BigInteger privateExponent, BigInteger modulus){ }
