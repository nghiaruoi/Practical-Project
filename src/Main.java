import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;

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
     * <code> java Main encrypt text.txt mypassword </code>
     * ====================================================================
     * <p> DECRYPT THE SYMMETRIC CRYPTOGRAM CREATED BY THE ENCRYPTION PROCESS ABOVE UNDER THE
     * USER-SUPPLIED PASSPHRASE </p>
     * <p> Decrypt the symmetric cryptogram: </p>
     * <code> java Main decrypt text.txt.encrypted mypassword </code>
     * <p></p>
     * ====================================================================
     * <p> GENERATE AN ELLIPTIC KEY PAIR FROM A GIVEN PASSPHRASE AND WRITE THE PUBLIC KEY TO A FILE. </p>
     *
     * <p> Generate a key pair from passphrase: </p>
     * <code> generate public_key.bin mypassphrase </code>
     * ====================================================================
     * <p> ENCRYPT A DATA FILE WITH ECIES UNDER A GIVEN ELLIPTIC PUBLIC KEY FILE, AND WRITE THE CIPHERTEXT TO A FILE. </p>
     *
     * <p> Encrypt data file: </p>
     * <code> encryptecies text.txt public_key.bin </code>
     * ====================================================================
     * <p> DECRYPT WITH ECIES A GIVEN ELLIPTIC-ENCRYPTED FILE FROM A PASSWORD-DERIVED PRIVATE KEY AND WRITE THE DECRYPTED DATA TO A FILE. </p>
     *
     * <p> Decrypt a data file: </p>
     * <code> decryptecies ECIES-encrypted.bin mypassphrase </code>
     * ====================================================================
     * <p> SIGN WITH SCHNORR A GIVEN FILE FROM A PASSWORD-DERIVED PRIVATE KEY AND WRITE THE SIGNATURE TO A FILE. </p>
     *
     * <p> Sign a given file: </p>
     * <code> signature text.txt signature.bin mypassphrase </code>
     * ====================================================================
     * <p> VERIFY WITH SCHNORR A GIVEN DATA FILE AND ITS SIGNATURE FILE UNDER A GIVEN PUBLIC KEY FILE. </p>
     *
     * <p> Verify a signature: </p>
     * <code> verify text.txt signature.bin public_key.bin </code>
     * ====================================================================
     * <p> SUPPORTING MATERIAL: </p>
     * <code> https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c </code> <br>
     * <code> https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf </code> <br>
     * <code> https://emn178.github.io/online-tools/cshake128/ </code>
     */

    private static final SecureRandom random = new SecureRandom();
    private static final int KEY_LENGTH = 128 / 8; // 128 bits in bytes
    private static final int NONCE_LENGTH = 128 / 8; // 128 bits in bytes
    private static final String FILE_PATH = "./src/output-file/";

    public static void main(String[] args) {
        handleCommand(args);
    }

    public static void handleCommand(String[] args) {
        String operation = args[0].toLowerCase();
        String file;
        String passphrase;
        String dataFile;
        String signatureFile;

        try {
            switch (operation) {
                case "hash":
                    file = FILE_PATH + args[1];

                    try {
                        computeHash(file);
                        System.out.println("Successfully compute hash data.");
                    } catch (IOException e) {
                        System.err.println("Error reading file: " + e.getMessage());
                    }
                    break;
                case "mac":
                    file = FILE_PATH + args[1];
                    passphrase = args.length > 2 ? args[2] : null;
                    int outputLengthBits = args.length > 3 ? Integer.parseInt(args[3]) : 0;
                    if (passphrase == null) {
                        System.out.println("Passphrase is required for MAC operation");
                        return;
                    }
                    if (outputLengthBits % 8 != 0) {
                        System.out.println("Output length must be a multiple of 8 bits");
                        return;
                    }
                    if (outputLengthBits == 0) {
                        System.out.println("Output length is required for MAC operation");
                        return;
                    }

                    try {
                        computeMac(file, passphrase, outputLengthBits);
                        System.out.println("Successfully compute MAC.");
                    } catch (IOException e) {
                        System.err.println("Error reading file: " + e.getMessage());
                    }
                    break;
                case "encrypt":
                    // text.txt will be encrypted
                    // output file is text.txt.encrypted
                    file = FILE_PATH + args[1];
                    passphrase = args.length > 2 ? args[2] : null;

                    if (passphrase == null) {
                        System.out.println("Passphrase is required for encryption");
                        return;
                    }
                    try {
                        encryptFile(file, passphrase);
                        System.out.println("Successfully encrypted file.");
                    } catch (IOException e) {
                        System.err.println("Error reading file: " + e.getMessage());
                    }
                    break;
                case "decrypt":
                    // text.txt.encrypted will be decrypted
                    // output file is text.txt.encrypted.decrypted
                    file = FILE_PATH + args[1];
                    passphrase = args.length > 2 ? args[2] : null;
                    if (passphrase == null) {
                        System.out.println("Passphrase is required for decryption");
                        return;
                    }

                    try {
                        if (decryptFile(file, passphrase)) {
                            System.out.println("Successfully decrypted file.");
                        } else {
                            System.out.println("Unable to decrypt file.");
                        }
                    } catch (IOException e) {
                        System.out.println("Error reading file: " + e.getMessage());
                    }
                    break;
                case "generate":
                    // output file is public_key.bin
                    file = FILE_PATH + args[1];
                    passphrase = args.length > 2 ? args[2] : null;
                    if (passphrase == null) {
                        System.out.println("Passphrase is required for generating keypair");
                        return;
                    }

                    try {
                        generateKeyPair(passphrase, file);
                        System.out.println("Successfully generated keypair.");
                    } catch (IOException e) {
                        System.out.println("Error reading file: " + e.getMessage());
                    }
                    break;
                case "encryptecies":
                    // input file is text.txt
                    // output file is encrypted.bin
                    final String FILE_ENCRYPTED = "ECIES-encrypted.bin";
                    file = FILE_PATH + args[1];
                    String publicKeyFile = FILE_PATH + args[2];
                    String encrypted_output = FILE_PATH + FILE_ENCRYPTED;

                    try {
                        encryptFile(file, publicKeyFile, encrypted_output);
                        System.out.println("Successfully ECIES encrypted file.");
                    } catch (IOException e) {
                        System.out.println("Error reading file: " + e.getMessage());
                    }
                    break;
                case "decryptecies":
                    // output file is decrypted.txt
                    // passphrase is mypassphrase
                    final String FILE_DECRYPTED = "ECIES-decrypted.txt";
                    file = FILE_PATH + args[1];
                    String outputFile = FILE_PATH + FILE_DECRYPTED;
                    passphrase = args[2];

                    try {
                        if (decryptFile(file, outputFile, passphrase)) {
                            System.out.println("Successfully decrypted ECIES file.");
                        } else {
                            System.out.println("Unable to decrypt file.");
                        }
                    } catch (IOException e) {
                        System.out.println("Error reading file: " + e.getMessage());
                    }
                    break;
                case "signature":
                    dataFile = FILE_PATH + args[1];
                    signatureFile = FILE_PATH + args[2];
                    passphrase = args[3];

                    try {
                        signFileWithSchnorr(dataFile, signatureFile, passphrase);
                        System.out.println("Signed data written to: " + signatureFile);
                    } catch (IOException e) {
                        System.err.println("Error signing file: " + e.getMessage());
                    }
                    break;
                case "verify":
                    dataFile = FILE_PATH + args[1];
                    signatureFile = FILE_PATH + args[2];
                    publicKeyFile = FILE_PATH + args[3];

                    try {
                        if (verifySignature(dataFile, signatureFile, publicKeyFile)) {
                            System.out.println("Successfully verified file.");
                        } else {
                            System.out.println("Unable to verify signature");
                        }
                    } catch (IOException e) {
                        System.out.println("Error reading file: " + e.getMessage());
                    }
                    break;
                default:
                    System.out.println("Unknown operation: " + operation);
            }
        } catch (IOException e) {
            System.out.println("Error reading file: " + e.getMessage());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Compute the SHA-3-256, SHA-3-512, SHA-3-224, and SHA-3-384 hashes for a user-specified file.
     */
    public static void computeHash(String filePath) throws IOException {
        byte[] fileContent = readFile(filePath);

        byte[] sha3_224 = SHA3SHAKE.SHA3(224, fileContent, null);
        byte[] sha3_256 = SHA3SHAKE.SHA3(256, fileContent, null);
        byte[] sha3_384 = SHA3SHAKE.SHA3(384, fileContent, null);
        byte[] sha3_512 = SHA3SHAKE.SHA3(512, fileContent, null);

        System.out.println("SHA3-224: " + SHA3SHAKE.convertBytesToString(sha3_224));
        System.out.println("SHA3-256: " + SHA3SHAKE.convertBytesToString(sha3_256));
        System.out.println("SHA3-384: " + SHA3SHAKE.convertBytesToString(sha3_384));
        System.out.println("SHA3-512: " + SHA3SHAKE.convertBytesToString(sha3_512));
    }

    /**
     * Compute SHAKE-128 and SHAKE-256 authentication tags (MACs) of user-specified
     * length for a user-specified file or user-input text under a user-specified passphrase.
     */
    private static void computeMac(String argument, String passphrase, int outputLength) throws IOException {
        boolean isFile = argument.endsWith(".txt");
        byte[] fileContent = new byte[0];
        if (isFile) {
            try {
                fileContent = readFile(argument);
            } catch (IOException e) {
                System.out.println("Error reading file: " + e.getMessage());
            }
        } else {
            String fileContentString = argument.split("/")[2];
            fileContent = fileContentString.getBytes();
        }

        SHA3SHAKE.MAC(fileContent, passphrase, outputLength);
    }

    /**
     * Generates a key pair and saves the public key to a file.
     * This method generates an elliptic curve key pair based on a given passphrase,
     * saves the public key to a specified file, and prints the key information.
     *
     * @param passphrase    The passphrase used to generate the key pair.
     * @param publicKeyFile The path where the public key will be saved.
     * @throws IOException If an I/O error occurs while writing the public key file.
     */
    public static void generateKeyPair(String passphrase, String publicKeyFile) throws IOException {
        EllipticCurve.KeyPair keyPair = EllipticCurve.generateKeyPair(passphrase);
        BigInteger s = keyPair.privateKey();
        Edwards.Point V = keyPair.publicKey();

        try (DataOutputStream dos = new DataOutputStream(new FileOutputStream(publicKeyFile))) {
            // Write lengths of x and y
            int xLength = V.getX().toByteArray().length;
            int yLength = V.getY().toByteArray().length;
            dos.writeInt(xLength);
            dos.writeInt(yLength);

            dos.write(V.getX().toByteArray());
            dos.write(V.getY().toByteArray());
        }

        System.out.println("Private Key: " + s);
        System.out.println("Public Key: " + V);
    }

    /**
     * Encrypt a user-specified data file symmetrically under a user-supplied passphrase
     */
    private static void encryptFile(String filePath, String passphrase) throws IOException {
        byte[] fileContent = readFile(filePath);
        String encryptedFile = ".encrypted";
        // Generate symmetric key from passphrase
        byte[] key = SHA3SHAKE.SHAKE(128, passphrase.getBytes(), 128, null);

        // Generate random nonce
        byte[] nonce = new byte[NONCE_LENGTH];
        random.nextBytes(nonce);

        // Encrypt the data
        SHA3SHAKE shake = new SHA3SHAKE();
        shake.init(128);
        shake.absorb(nonce);
        shake.absorb(key);
        byte[] keystream = shake.squeeze(fileContent.length);

        byte[] encryptedData = new byte[fileContent.length];
        for (int i = 0; i < fileContent.length; i++) {
            encryptedData[i] = (byte) (fileContent[i] ^ keystream[i]);
        }

        shake.init(256);
        shake.absorb(key);
        shake.absorb(encryptedData);
        byte[] macTag = shake.digest();

        // Append MAC to cryptogram
        byte[] cryptogramWithMac = new byte[nonce.length + encryptedData.length + macTag.length];
        System.arraycopy(nonce, 0, cryptogramWithMac, 0, nonce.length);
        System.arraycopy(encryptedData, 0, cryptogramWithMac, nonce.length, encryptedData.length);
        System.arraycopy(macTag, 0, cryptogramWithMac, nonce.length + encryptedData.length, macTag.length);

        String encryptedFileWithMACPath = filePath + encryptedFile;
        try (FileOutputStream fos = new FileOutputStream(encryptedFileWithMACPath)) {
            fos.write(cryptogramWithMac);
            System.out.println("Encrypted file saved as: " + encryptedFileWithMACPath);
        } catch (IOException e) {
            System.err.println("Error writing file: " + e.getMessage());
        }
    }

    /**
     * Decrypts a file using a passphrase-based symmetric encryption scheme.
     * <p></p>
     * This method reads an encrypted file, derives a key from the provided passphrase,
     * and decrypts the file contents using a stream cipher based on SHAKE-128. The
     * decrypted content is then written to a new file with a ".decrypted" extension.
     *
     * @param filePath   The path to the encrypted file.
     * @param passphrase The passphrase used for decryption.
     * @return true if the decrypted file matches the original file, false otherwise.
     * @throws IOException If an I/O error occurs during file reading or writing.
     */
    private static boolean decryptFile(String filePath, String passphrase) throws IOException {
        String fileName = "text.txt";
        Path originalFile = Paths.get(FILE_PATH + fileName);

        // Read the encrypted data from the file
        byte[] cryptogram = readFile(filePath);

        // Extract nonce, ciphertext, and MAC
        byte[] nonce = Arrays.copyOfRange(cryptogram, 0, 16);
        byte[] ciphertext = Arrays.copyOfRange(cryptogram, 16, cryptogram.length - 32);
        byte[] storedMac = Arrays.copyOfRange(cryptogram, cryptogram.length - 32, cryptogram.length);

        // Generate symmetric key from passphrase using SHAKE-128
        byte[] key = SHA3SHAKE.SHAKE(128, passphrase.getBytes(), 128, null);

        // Initialize SHAKE-128 for key-stream generation
        SHA3SHAKE shake = new SHA3SHAKE();
        shake.init(128);
        shake.absorb(nonce);
        shake.absorb(key);

        byte[] keystream = shake.squeeze(ciphertext.length);
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

        shake.init(256);
        shake.absorb(key);
        shake.absorb(ciphertext);
        byte[] computedMac = shake.digest();

        return Files.mismatch(originalFile, Paths.get(outputFilePath)) == -1 && Arrays.equals(computedMac, storedMac);
    }

    /**
     * Encrypts a data file using ECIES under a given elliptic public key and writes the ciphertext to a file.
     *
     * @param dataFile     Path to the input file to be encrypted.
     * @param publicKeyFile Path to the file containing the elliptic public key.
     * @param outputFile    Path to the output file where the ciphertext will be written.
     * @throws IOException If there's an error reading or writing files.
     */
    public static void encryptFile(String dataFile, String publicKeyFile, String outputFile) throws IOException {
        // Read the public key from file
        Edwards.Point V = readPublicKeyFromFile(publicKeyFile);

        // Read the input file
        byte[] message = readByteArrayFromFile(dataFile);

        // Encrypt the message
        EllipticCurve.Cryptogram cryptogram = EllipticCurve.encrypt(message, V);
        System.out.println("X: " + cryptogram.Z().getX().toString());
        System.out.println("Y: " + cryptogram.Z().getY().toString());

        // Write the cryptogram to the output file
        try (DataOutputStream dos = new DataOutputStream(new FileOutputStream(outputFile))) {
            // Write lengths of x and y
            int xLength = cryptogram.Z().getX().toByteArray().length;
            int yLength = cryptogram.Z().getY().toByteArray().length;
            dos.writeInt(xLength);
            dos.writeInt(yLength);

            // Write Z (x and y coordinates)
            dos.write(cryptogram.Z().getX().toByteArray());
            dos.write(cryptogram.Z().getY().toByteArray());

            dos.writeInt(cryptogram.c().length);
            dos.write(cryptogram.c());

            // Write authentication tag
            dos.write(cryptogram.t());
        }

        System.out.println("Encrypted file saved as: " + outputFile);
    }

    /**
     * Decrypts an elliptic-encrypted file using ECIES with a password-derived private key.
     *
     * @param inputFile  Path to the encrypted input file.
     * @param outputFile Path to the file where decrypted data will be written.
     * @param passphrase The passphrase used to derive the private key.
     * @return true if the decrypted file matches the original file, false otherwise.
     * @throws IOException If there's an error reading or writing files.
     * @throws Exception   If decryption fails due to authentication error.
     */
    public static boolean decryptFile(String inputFile, String outputFile, String passphrase) throws IOException, Exception {
        String fileName = "bin-text.txt";
        Path originalFile = Paths.get(FILE_PATH + fileName);

        // Read the encrypted file
        try (DataInputStream dis = new DataInputStream(new FileInputStream(inputFile))) {
            // Read lengths of x and y
            int xLength = dis.readInt();
            int yLength = dis.readInt();

            // Read x and y coordinates
            byte[] xBytes = new byte[xLength];
            dis.readFully(xBytes);
            BigInteger x = new BigInteger(1, xBytes);

            byte[] yBytes = new byte[yLength];
            dis.readFully(yBytes);
            BigInteger y = new BigInteger(1, yBytes);
//            Edwards Edwards = new Edwards();
//            Edwards.Point Z = Edwards.getPoint(y, x.testBit(0));

            Edwards.Point Z = new Edwards().getPoint(y, x.testBit(0));
            // Read ciphertext
            int cLength = dis.readInt();
            byte[] c = new byte[cLength];
            dis.readFully(c);

            // Read authentication tag
            byte[] t = new byte[32]; // Assuming 256-bit tag
            dis.readFully(t);

            // Create Cryptogram object
            EllipticCurve.Cryptogram cryptogram = new EllipticCurve.Cryptogram(Z, c, t);

            // Decrypt the cryptogram
            byte[] decryptedData = EllipticCurve.decrypt(cryptogram, passphrase);
            String decryptedDataString = byteArrayToHexString(decryptedData);
            // Write decrypted data to output file
            try (FileWriter writer = new FileWriter(outputFile)) {
                writer.write(decryptedDataString);
            } catch (IOException e) {
                System.err.println("Error writing decrypted data to file: " + e.getMessage());
            }

            System.out.println("Decrypted file saved as: " + outputFile);
        }
        return Files.mismatch(originalFile, Paths.get(outputFile)) == -1;
    }

    /**
     * Signs a file using the Schnorr signature scheme.
     * <p></p>
     * This method reads the contents of an input file, generates a Schnorr signature
     * using a passphrase-derived private key, and writes the signature to an output file.
     *
     * @param dataFile      The path to the file to be signed.
     * @param signatureFile The path where the signature will be saved.
     * @param passphrase    The passphrase used to generate the private key.
     * @throws IOException If an I/O error occurs while reading the input file or writing the signature file.
     */
    public static void signFileWithSchnorr(String dataFile, String signatureFile, String passphrase) throws IOException {
        // Read the input file
        byte[] message = readByteArrayFromFile(dataFile);

        // Generate the private key from the passphrase
        EllipticCurve.KeyPair keyPair = EllipticCurve.generateKeyPair(passphrase);
        BigInteger s = keyPair.privateKey();

        // Generate the signature
        EllipticCurve.Signature signature = EllipticCurve.generateSignature(message, s);

        // Write the signature to the output file
        try (DataOutputStream dos = new DataOutputStream(new FileOutputStream(signatureFile))) {
            int hLength = signature.h().toByteArray().length;
            int zLength = signature.z().toByteArray().length;

            dos.writeInt(hLength);
            dos.writeInt(zLength);

            dos.write(signature.h().toByteArray());
            dos.write(signature.z().toByteArray());
        }
    }

    public static boolean verifySignature(String dataFile, String signatureFile, String publicKeyFile) throws IOException {
        // Read the input file
        byte[] message = readByteArrayFromFile(dataFile);

        Edwards.Point V = readPublicKeyFromFile(publicKeyFile);

        EllipticCurve.Signature signature = readSignature(signatureFile);
        BigInteger h = signature.h();
        BigInteger z = signature.z();

        return EllipticCurve.verifySignature(message, new EllipticCurve.Signature(h, z), V);
    }

    //**********************************************************
    //                      Helper Methods                      *

    /**
     * Generates a symmetric key from a passphrase using SHAKE-128.
     *
     * @param passphrase The user-supplied passphrase.
     * @return A 128-bit symmetric key.
     */
    private static byte[] generateKey(String passphrase) {
        SHA3SHAKE shake128 = new SHA3SHAKE();
        shake128.init(128); // Use SHAKE-128
        shake128.absorb(passphrase.getBytes());
        return shake128.squeeze(KEY_LENGTH);
    }

    /**
     * Generates a random 128-bit nonce.
     *
     * @return A randomly generated nonce.
     */
    private static byte[] generateNonce() {
        byte[] nonce = new byte[NONCE_LENGTH];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    /**
     * Reads a public key from a file and returns it as an Edwards.Point object.
     * This method reads the x and y coordinates of an Edwards curve point from a file
     * and constructs an Edwards.Point object representing the public key.
     *
     * @param publicKeyFile The path to the file containing the public key.
     * @return An Edwards.Point object representing the public key.
     * @throws IOException If an I/O error occurs while reading the file.
     */
    private static Edwards.Point readPublicKeyFromFile(String publicKeyFile) throws IOException {
        try (DataInputStream dis = new DataInputStream(new FileInputStream(publicKeyFile))) {
            int xLength = dis.readInt();
            int yLength = dis.readInt();

            byte[] xBytes = new byte[xLength];
            dis.readFully(xBytes);
            byte[] yBytes = new byte[yLength];
            dis.readFully(yBytes);

            BigInteger x = new BigInteger(1, xBytes);
            BigInteger y = new BigInteger(1, yBytes);
            return new Edwards().getPoint(y, x.testBit(0));
        }
    }

    /**
     * Reads a Schnorr signature from a file.
     *
     * @param signatureFile The path to the file containing the signature.
     * @return An EllipticCurve.Signature object representing the read signature.
     * @throws IOException If there's an error reading from the file.
     */
    private static EllipticCurve.Signature readSignature(String signatureFile) throws IOException {
        try (DataInputStream dis = new DataInputStream(new FileInputStream(signatureFile))) {
            int hLength = dis.readInt();
            int zLength = dis.readInt();

            byte[] hBytes = new byte[hLength];
            byte[] zBytes = new byte[zLength];
            dis.readFully(hBytes);
            dis.readFully(zBytes);

            BigInteger h = new BigInteger(1, hBytes);
            BigInteger z = new BigInteger(1, zBytes);

            return new EllipticCurve.Signature(h, z);
        }
    }

    /**
     * Reads the entire contents of a file into a byte array.
     * This method reads a file specified by the given file path and returns its contents
     * as a byte array. It uses a FileInputStream to read the file and ensures that the
     * entire file is read.
     *
     * @param filePath The path to the file to be read.
     * @return A byte array containing the entire contents of the file.
     * @throws IOException       If an I/O error occurs while reading the file, or if the file
     *                           cannot be completely read.
     * @throws SecurityException If a security manager exists and its checkRead method
     *                           denies read access to the file.
     */
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

    /**
     * Reads a byte array from a file where each byte is represented as a hexadecimal string.
     * This method reads the first line of the specified file, expecting it to contain
     * space-separated hexadecimal values representing bytes. It then converts these
     * hexadecimal strings into a byte array.
     *
     * @param filePath The path to the file containing the byte data.
     * @return A byte array containing the data read from the file.
     * @throws IOException If an I/O error occurs while reading the file.
     * @throws NumberFormatException If the file contains invalid hexadecimal values.
     */
    public static byte[] readByteArrayFromFile(String filePath) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line = reader.readLine();
            // handle empty string when read from the file
            if (line == null || line.trim().isEmpty()) {
                return new byte[0];
            }
            String[] hexValues = line.trim().split("\\s+");
            byte[] byteArray = new byte[hexValues.length];
            for (int i = 0; i < hexValues.length; i++) {
                byteArray[i] = (byte) Integer.parseInt(hexValues[i], 16);
            }
            return byteArray;
        }
    }

    /**
     * Converts the given byte array to a hexadecimal string.
     *
     * @param bytes the given byte array
     * @return the hexadecimal string representation of the byte array
     */
    public static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().stripTrailing();
    }
}

