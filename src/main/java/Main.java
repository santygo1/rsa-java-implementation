import keys.KeyPair;
import keys.RSAPrivateKey;
import keys.RSAPublicKey;

import javax.sound.midi.Soundbank;
import java.math.BigInteger;
import java.util.stream.Collectors;

import static java.lang.StringTemplate.STR;

public class Main {

    private static final String BLOCK_DELIMITER = "-";

    public static void main(String[] args) {
        // Генерируем пару ключей - публичный и приватный
        RSAKeyGen keyGen = new RSAKeyGen(1024);
        KeyPair keyPair = keyGen.generateKeyPair();
        RSAPublicKey publicKey = keyPair.publicKey();
        RSAPrivateKey privateKey = keyPair.privateKey();
        System.out.println(STR."""
                Public key: \{publicKey}
                Private key: \{privateKey}
                """
        );

        String message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, " +
                "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam," +
                " quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat." +
                " Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. " +
                "Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
        System.out.println(STR."Message: \{message}");

        String cipherText = encrypt(message, publicKey); // шифруем сообщение
        System.out.println(STR."Encoded: \{cipherText}" + cipherText);

        String decodedMessage = decrypt(cipherText, privateKey); // дешифруем сообщение
        System.out.println(STR."Decoded: \{decodedMessage}");
    }

    // Шифрование
    public static String encrypt(String message, RSAPublicKey key) {
        StringBuilder encryptedMessage = new StringBuilder();
        int chunkSize = key.modulus().bitLength() >> 3; // определяем размер блока для шифрования
        byte[] bytes = message.getBytes(); // получаем байты исходного сообщения
        int index = 0;

        while (index < bytes.length) {
            byte[] block = new byte[Math.min(chunkSize, bytes.length - index)]; // формируем блок для шифрования
            System.arraycopy(bytes, index, block, 0, block.length);
            BigInteger blockAsInteger = new BigInteger(1, block); // создаем BigInteger из блока байтов
            BigInteger encryptedBlock = blockAsInteger.modPow(key.publicExponent(), key.modulus()); // шифруем блок
            encryptedMessage.append(encryptedBlock.toString()).append(BLOCK_DELIMITER); // добавляем зашифрованный блок к результату с пробелом
            index += block.length; // переходим к следующему блоку
        }
        return encryptedMessage.toString().trim(); // возвращаем зашифрованное сообщение как строку
    }

    // Расшифровка
    public static String decrypt(String message, RSAPrivateKey key) {
        StringBuilder decryptedMessage = new StringBuilder();
        String[] blocks = message.split(BLOCK_DELIMITER); // разбиваем зашифрованное сообщение на блоки
        for (String block : blocks) {
            BigInteger encryptedBlock = new BigInteger(block); // преобразуем блок в BigInteger
            BigInteger decryptedBlock = encryptedBlock.modPow(key.privateExponent(), key.modulus()); // дешифруем блок
            byte[] decryptedBytes = decryptedBlock.toByteArray(); // получаем байты дешифрованного блока
            decryptedMessage.append(new String(decryptedBytes)); // добавляем дешифрованные байты к результату
        }
        return decryptedMessage.toString(); // возвращаем исходное сообщение
    }
}
