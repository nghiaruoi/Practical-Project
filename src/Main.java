import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class Main {

    /**
     * ====================================================================
     * <p>
     * COMPUTE THE SHA-3-256 AND SHA-3-512 HASHES FOR A USER-SPECIFIED FILE
     * </p>
     * <p> Compute from a file: </p>
     * <code> java Main hash text.txt </code>
     * ====================================================================
     * <p> COMPUTE SHAKE-128 AND SHAKE-256 AUTHENTICATION TAGS (MACS) OF USER-SPECIFIED
     * LENGTH FOR A USER-SPECIFIED FILE UNDER A USER-SPECIFIED PASSPHRASE </p>
     * <p> Compute MAC from a file: </p>
     * <code> java Main mac text.txt mypassphrase 256 </code> <br>
     * <code> java Main mac text.txt mypassphrase 512 </code> <br>
     * <p> Compute MAC from text input by user: </p>
     * <code> java Main mac userinputtext mypassphrase 256 </code> <br>
     * <code> java Main mac userinputtext mypassphrase 512 </code> <br>
     * ====================================================================
     * <p> ENCRYPT A USER-SPECIFIED DATA FILE SYMMETRICALLY UNDER A USER-SUPPLIED PASSPHRASE </p>
     * <p> Encrypt a user-specified file: </p>
     * <code> java Main encrypt testfile.txt mypassword </code>
     * ====================================================================
     * <p> DECRYPT THE SYMMETRIC CRYPTOGRAM CREATED BY THE ENCRYPTION PROCESS ABOVE UNDER THE
     * USER-SUPPLIED PASSPHRASE </p>
     * <p> Decrypt the symmetric cryptogram: </p>
     * <code> java Main decrypt testfile.txt.encrypted mypassword </code>
     * <p></p>
     * ====================================================================
     * <p> SUPPORTING MATERIAL: </p>
     *  <code> https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c </code> <br>
     *  <code> https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf </code> <br>
     *  <code> https://emn178.github.io/online-tools/cshake128/ </code>
     */

    private static final SecureRandom random = new SecureRandom();
//    private static final BigInteger CURVE_ORDER_R = BigInteger.valueOf(2).pow(255).subtract(BigInteger.valueOf(19));

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

//                case "generate":
//                    passphrase = filePath;
//                    if (passphrase == null) {
//                        System.out.println("Passphrase is required for generating keypair");
//                    }
//                    generateKeyPair(passphrase);
//                    break;
                default:
                    System.out.println("Unknown operation: " + operation);
            }
        } catch (IOException e) {
            System.out.println("Error reading file: " + e.getMessage());
        }
    }

//    private static void generateKeyPair(String passphrase) {
//        // The order of the curve's base point G
//        final BigInteger r = new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989");
//
//        // Assuming you have an Edwards class that implements the curve operations
//        final Edwards curve = new Edwards();
//
//        SHA3SHAKE shake = new SHA3SHAKE();
//        shake.init(128);
//        shake.absorb(passphrase.getBytes(StandardCharsets.UTF_8));
//
//        // 2. Squeeze a 256-bit byte array
//        byte[] squeezed = shake.squeeze(32); // 32 bytes = 256 bits
//
//        // 3. Create a BigInteger from the squeezed bytes and reduce mod r
//        BigInteger s = new BigInteger(1, squeezed).mod(r);
//
//        // 4. Compute V = s * G
//        Edwards.Point G = curve.gen();
//        Edwards.Point V = G.mul(s);
//
//        // 5. Check the least significant bit of the x-coordinate of V
//        if (V.getX().testBit(0)) {
//            // If LSB is 1, replace s by r - s and V by -V
//            s = r.subtract(s);
//            V = V.negate();
//        }
//
//        System.out.println("Private Key: " + s);
//        System.out.println("Public Key: " + V.toString());
//    }

//    public static Cryptogram encrypt(Edwards.Point V, byte[] message) {
//        // Generate random 256-bit byte array
//        SecureRandom random = new SecureRandom();
//        byte[] randomBytes = new byte[32];
//        random.nextBytes(randomBytes);
//
//        // Convert to BigInteger and reduce mod r
//        BigInteger k = new BigInteger(1, randomBytes).mod(CURVE_ORDER_R);
//
//        // Compute W and Z
//        Edwards.Point G = new Edwards().gen();
//        Edwards.Point W = V.mul(k);
//        Edwards.Point Z = G.mul(k);
//
//        // Generate key material
//        SHA3SHAKE shake256 = new SHA3SHAKE();
//        shake256.init(256);
//        shake256.absorb(W.getY().toByteArray());
//        byte[] ka = shake256.squeeze(32);
//        byte[] ke = shake256.squeeze(32);
//
//        // Encrypt the message
//        SHA3SHAKE shake128 = new SHA3SHAKE();
//        shake128.init(128);
//        shake128.absorb(ke);
//        byte[] keystream = shake128.squeeze(message.length);
//        byte[] ciphertext = new byte[message.length];
//        for (int i = 0; i < message.length; i++) {
//            ciphertext[i] = (byte) (message[i] ^ keystream[i]);
//        }
//
//        // Generate authentication tag
//        SHA3SHAKE sha3 = new SHA3SHAKE();
//        sha3.init(256);
//        sha3.absorb(ka);
//        sha3.absorb(ciphertext);
//        byte[] t = sha3.digest();
//
//        return new Cryptogram(Z, ciphertext, t);
//    }

    /**
     * Compute the SHA-3-256, SHA-3-512, SHA-3-224, and SHA-3-384 hashes for a user-specified file.
     */
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

    /**
     * Compute MAC for both file and input text by user
     */
    private static void computeMac(String filePath, String passphrase, int outputLength) throws IOException {
        boolean isFile = filePath.endsWith(".txt");
        byte[] fileContent = new byte[0];
        if (isFile) {
            try {
                fileContent = readFile(filePath);
            } catch (IOException e) {
                System.out.println("Error reading file: " + e.getMessage());
            }
        } else {
            String fileContentString = filePath.split("/")[2];
            fileContent = fileContentString.getBytes();
        }

        SHA3SHAKE.MAC(fileContent, passphrase, outputLength);
    }

    /**
     * Encrypt a user-specified data file symmetrically under a user-supplied passphrase
     */
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

    /**
     * Decrypt the symmetric cryptogram created by the encryption process above under the
     * user-supplied passphrase.
     */
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

    /************************************************************
     *                      Helper Methods                      *
     ************************************************************/

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

//    public static class Cryptogram {
//        public final Edwards.Point Z;
//        public final byte[] ciphertext;
//        public final byte[] tag;
//
//        public Cryptogram(Edwards.Point Z, byte[] ciphertext, byte[] tag) {
//            this.Z = Z;
//            this.ciphertext = ciphertext;
//            this.tag = tag;
//        }
//    }
}

