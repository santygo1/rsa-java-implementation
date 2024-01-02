import keys.KeyPair;
import keys.RSAPrivateKey;
import keys.RSAPublicKey;

import java.math.BigInteger;
import java.util.Random;

public class RSAKeyGen {
    private final int keySize;
    public RSAKeyGen(int keySize){
        if (keySize < 8){
            throw new IllegalArgumentException("keySize должен быть больше либо равен 8");
        }
        if ((keySize & (keySize -1)) != 0){
            throw new IllegalArgumentException("keySize не является степенью двойки");
        }
        this.keySize = keySize;
    }

    public KeyPair generateKeyPair(){
        Random random = new Random();

        BigInteger q = BigInteger.probablePrime(keySize/2, random);
        BigInteger p = BigInteger.probablePrime(keySize/2, random);

        BigInteger modules = q.multiply(p); // n = q*p
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)); // (p-1)*(q-1)
        BigInteger publicExponent;
        do {
            publicExponent = new BigInteger(phi.bitLength(), random);
        }while (!publicExponent.gcd(phi).equals(BigInteger.ONE));

        BigInteger privateExponent = publicExponent.modInverse(phi);

        RSAPublicKey publicKey = new RSAPublicKey(publicExponent, modules);
        RSAPrivateKey privateKey = new RSAPrivateKey(privateExponent, modules);
        return new KeyPair(publicKey, privateKey);
    }
}
