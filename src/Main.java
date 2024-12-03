import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class Main {

    /*

     */

    private static final SecureRandom random = new SecureRandom();

    public static void main(String[] args) {
        handleCommand(args);
    }

    public static void handleCommand(String[] args) {
        String operation = args[0].toLowerCase();
        String filePath = "./src/" + args[1];
        String passphrase = args.length > 2 ? args[2] : null;
        int outputLengthBits = args.length > 3 ? Integer.parseInt(args[3]) : 0;

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

                case "generate":
                    passphrase = filePath;
                    if (passphrase == null) {
                        System.out.println("Passphrase is required for generating keypair");
                    }
                    generateKeyPair(passphrase);
                    break;
                default:
                    System.out.println("Unknown operation: " + operation);
            }
        } catch (IOException e) {
            System.out.println("Error reading file: " + e.getMessage());
        }
    }

    private static void generateKeyPair(String passphrase) {
        // The order of the curve's base point G
        final BigInteger r = new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989");

        // Assuming you have an Edwards class that implements the curve operations
        final Edwards curve = new Edwards();

        SHA3SHAKE shake = new SHA3SHAKE();
        shake.init(128);
        shake.absorb(passphrase.getBytes(StandardCharsets.UTF_8));

        // 2. Squeeze a 256-bit byte array
        byte[] squeezed = shake.squeeze(32); // 32 bytes = 256 bits

        // 3. Create a BigInteger from the squeezed bytes and reduce mod r
        BigInteger s = new BigInteger(1, squeezed).mod(r);

        // 4. Compute V = s * G
        Edwards.Point G = curve.gen();
        Edwards.Point V = G.mul(s);

        // 5. Check the least significant bit of the x-coordinate of V
        if (V.getX().testBit(0)) {
            // If LSB is 1, replace s by r - s and V by -V
            s = r.subtract(s);
            V = V.negate();
        }

        System.out.println("Private Key: " + s);
        System.out.println("Public Key: " + V.toString());
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

        SHA3SHAKE.MAC(fileContent, passphrase, outputLength);
    }

    private static void encryptFile(String filePath, String passphrase) throws IOException {
        byte[] fileContent = readFile(filePath);
        // Generate symmetric key from passphrase
        byte[] key = SHA3SHAKE.SHAKE(128, passphrase.getBytes(), 128, null);

        // Generate random nonce
        byte[] nonce = new byte[16];
        random.nextBytes(nonce);

        // Encrypt the data
        SHA3SHAKE shake = new SHA3SHAKE();
        shake.init(128);
        shake.absorb(nonce);
        shake.absorb(key);
        byte[] keystream = shake.squeeze(fileContent.length);

        byte[] ciphertext = new byte[fileContent.length];
        for (int i = 0; i < fileContent.length; i++) {
            ciphertext[i] = (byte) (fileContent[i] ^ keystream[i]);
        }

        // Combine nonce, ciphertext
        byte[] cryptogram = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, cryptogram, 0, nonce.length);
        System.arraycopy(ciphertext, 0, cryptogram, nonce.length, ciphertext.length);

        // Write the cryptogram to a file
        String encryptedFilePath = filePath + ".encrypted";
        try (FileOutputStream fos = new FileOutputStream(encryptedFilePath)) {
            fos.write(cryptogram);
        } catch (IOException e) {
            System.err.println("Error writing file: " + e.getMessage());
        }

        System.out.println(HexUtils.convertBytesToString(cryptogram));
        System.out.println("File encrypted successfully. Encrypted file saved as: " + encryptedFilePath);
    }

    private static void decryptFile(String filePath, String passphrase) throws IOException {
        // Read the encrypted data from the file
        byte[] encryptedData = readFile(filePath);

        // Generate symmetric key from passphrase using SHAKE-128
        byte[] key = SHA3SHAKE.SHAKE(128, passphrase.getBytes(), 128, null);

        // Extract the nonce (first 16 bytes) from the encrypted data
        byte[] nonce = new byte[16];
        System.arraycopy(encryptedData, 0, nonce, 0, 16);

        // Extract the ciphertext (remaining bytes after nonce)
        byte[] ciphertext = new byte[encryptedData.length - 16];
        System.arraycopy(encryptedData, 16, ciphertext, 0, ciphertext.length);

        // Initialize SHAKE-128 for key-stream generation
        SHA3SHAKE shake = new SHA3SHAKE();
        shake.init(128);
        shake.absorb(nonce);
        shake.absorb(key);

        // Generate key-stream of the same length as the ciphertext
        byte[] keystream = shake.squeeze(ciphertext.length);

        // Decrypt the ciphertext by XORing with the key-stream
        byte[] plaintext = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i++) {
            plaintext[i] = (byte) (ciphertext[i] ^ keystream[i]);
        }

        // Write the decrypted data to a new file
        String outputFilePath = filePath + ".decrypted";
        try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
            fos.write(plaintext);
            System.out.println("Decrypted data written to: " + outputFilePath);
        } catch (IOException e) {
            System.err.println("Error writing decrypted data to file: " + e.getMessage());
        }
    }

    private static byte[] readFile(String filePath) throws IOException {
        File file = new File(filePath);
        byte[] fileContent = new byte[(int) file.length()];

        try (FileInputStream fis = new FileInputStream(file)) {
            int bytesRead = fis.read(fileContent);
            if (bytesRead != fileContent.length) {
                throw new IOException("Could not completely read the file " + file.getName());
            }
        }

        return fileContent;
    }
}

