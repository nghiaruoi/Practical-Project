import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.SecureRandom;

public class Main {

    /*
    https://www.youtube.com/watch?v=WnXQl-HUS7I&t=3s&ab_channel=AndrewChabot
     */

    private static final SecureRandom random = new SecureRandom();

    public static void main(String[] args) {
        handleCommand(args);
    }

    public static void handleCommand(String[] args) {
        String operation = args[0].toLowerCase();
        String filePath = "./src/" + args[1];
        String passphrase = args.length > 2 ? args[2] : null;
        int outputLengthBits = args.length > 3 ?  Integer.parseInt(args[3]) : 0;

        if (outputLengthBits % 8 != 0) {
            System.out.println("Output length must be a multiple of 8 bits");
            return;
        }

        try {
            switch (operation) {
                case "hash":
                    computeHash(filePath);
                    break;
                case "mac":
                    if (passphrase == null) {
                        System.out.println("Passphrase is required for MAC operation");
                        return;
                    }
                    if (outputLengthBits == 0) {
                        System.out.println("Output length is required for MAC operation");
                        return;
                    }
                    computeMac(filePath, passphrase, outputLengthBits);
                    break;
                case "encrypt":
                    if (passphrase == null) {
                        System.out.println("Passphrase is required for encryption");
                        return;
                    }
                    encryptFile(filePath, passphrase);
                    break;
                case "decrypt":
                    if (passphrase == null) {
                        System.out.println("Passphrase is required for decryption");
                        return;
                    }
                    decryptFile(filePath, passphrase);
                    break;
                default:
                    System.out.println("Unknown operation: " + operation);
            }
        } catch (IOException e) {
            System.out.println("Error reading file: " + e.getMessage());
        }
    }

    public static void computeHash(String filePath) throws IOException {
        byte[] fileContent = readFile(filePath);

        byte[] sha3_224 = SHA3SHAKE.SHA3(224, fileContent, null);
        byte[] sha3_256 = SHA3SHAKE.SHA3(256, fileContent, null);
        byte[] sha3_384 = SHA3SHAKE.SHA3(384, fileContent, null);
        byte[] sha3_512 = SHA3SHAKE.SHA3(512, fileContent, null);

        System.out.println("SHA3-224: " + HexUtils.convertBytesToString(sha3_224));
        System.out.println("SHA3-256: " + HexUtils.convertBytesToString(sha3_256));
        System.out.println("SHA3-384: " + HexUtils.convertBytesToString(sha3_384));
        System.out.println("SHA3-512: " + HexUtils.convertBytesToString(sha3_512));
    }

    private static void computeMac(String filePath, String passphrase, int outputLength) throws IOException {
        byte[] fileContent = new byte[0];
        try {
            fileContent = readFile(filePath);
        } catch (IOException e) {
            System.out.println("Error reading file: " + e.getMessage());
        }

        SHA3SHAKE shake = new SHA3SHAKE();
        SHA3SHAKE.MAC(fileContent, passphrase, outputLength);
    }

    private static void encryptFile(String filePath, String passphrase) throws IOException {
        byte[] fileContent = readFile(filePath);
        byte[] key = SHA3SHAKE.SHAKE(128, passphrase.getBytes(), 128, null);
        byte[] nonce = new byte[16];
        random.nextBytes(nonce);

        SHA3SHAKE shake = new SHA3SHAKE();
        shake.init(128);
        shake.absorb(nonce);
        shake.absorb(key);
        byte[] keystream = shake.squeeze(fileContent.length);

        byte[] ciphertext = new byte[fileContent.length];
        for (int i = 0; i < fileContent.length; i++) {
            ciphertext[i] = (byte) (fileContent[i] ^ keystream[i]);
        }

        byte[] encryptedData = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, encryptedData, 0, nonce.length);
        System.arraycopy(ciphertext, 0, encryptedData, nonce.length, ciphertext.length);

        // Write encryptedData to a file
        // For simplicity, we're just printing it here
        System.out.println("Encrypted data: " + bytesToHex(encryptedData));
    }

    private static void decryptFile(String filePath, String passphrase) throws IOException {
        byte[] encryptedData = readFile(filePath);
        byte[] key = SHA3SHAKE.SHAKE(128, passphrase.getBytes(), 128, null);

        byte[] nonce = new byte[16];
        System.arraycopy(encryptedData, 0, nonce, 0, 16);

        byte[] ciphertext = new byte[encryptedData.length - 16];
        System.arraycopy(encryptedData, 16, ciphertext, 0, ciphertext.length);

        SHA3SHAKE shake = new SHA3SHAKE();
        shake.init(128);
        shake.absorb(nonce);
        shake.absorb(key);
        byte[] keystream = shake.squeeze(ciphertext.length);

        byte[] plaintext = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i++) {
            plaintext[i] = (byte) (ciphertext[i] ^ keystream[i]);
        }

        // Write plaintext to a file
        // For simplicity, we're just printing it here
        System.out.println("Decrypted data: " + new String(plaintext));
    }

    private static byte[] readFile(String filePath) throws IOException {
        File file = new File(filePath);
        byte[] fileContent = new byte[(int) file.length()];
        FileInputStream fis = new FileInputStream(file);
        fis.read(fileContent);
        fis.close();
        return fileContent;
    }


    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }


}

