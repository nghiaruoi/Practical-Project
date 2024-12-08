import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

public class EllipticCurve {
    private static final BigInteger CURVE_ORDER_R = BigInteger.valueOf(2).pow(254).subtract(new BigInteger("87175310462106073678594642380840586067"));
    private static final int MAC_LENGTH = 32; // SHA3-256 output size in bytes
    private static final SecureRandom random = new SecureRandom();

    /**
     * Generates a Schnorr/DHIES key pair from a given passphrase.
     *
     * @param passphrase    The user-supplied passphrase used to generate the key pair.
     * @return A KeyPair object containing the generated private key (s) and public key (V).
     */
    public static KeyPair generateKeyPair(String passphrase) {
        // The order of the E's base point G
        final BigInteger r = CURVE_ORDER_R;
        final Edwards E = new Edwards();

        SHA3SHAKE shake = new SHA3SHAKE();
        shake.init(128);
        shake.absorb(passphrase.getBytes(StandardCharsets.UTF_8));
        byte[] privateKeyBytes = shake.squeeze(32); // 32 bytes = 256 bits
        BigInteger s = new BigInteger(1, privateKeyBytes).mod(r);

        // 4. Compute V = s * G
        Edwards.Point G = E.gen();
        Edwards.Point V = G.mul(s);

        // 5. Check the least significant bit of the x-coordinate of V
        if (V.getX().testBit(0)) {
            // If LSB is 1, replace s by r - s and V by -V
            s = r.subtract(s);
            V = V.negate();
        }

        return new KeyPair(s, V);
    }

    /**
     * Encrypts a byte array message using the ECIES (Elliptic Curve Integrated Encryption Scheme) under a given public key.
     *
     * @param message The byte array message to be encrypted.
     * @param V       The public key as an Edwards curve point.
     * @return A Cryptogram object containing the encrypted message and associated data.
     */
    public static Cryptogram encrypt(byte[] message, Edwards.Point V) {
        Edwards E = new Edwards();
        SHA3SHAKE shake = new SHA3SHAKE();
        BigInteger r = CURVE_ORDER_R;

        // Generate random k
        int rbytes = (r.bitLength() + 7) >> 3;
        BigInteger k = new BigInteger(new SecureRandom().generateSeed(rbytes << 1)).mod(r);

        // Compute W and Z
        Edwards.Point W = V.mul(k);
        Edwards.Point Z = E.gen().mul(k);

        // Generate ka and ke
        shake.init(256);
        shake.absorb(W.getY().toByteArray());
        byte[] ka = shake.squeeze(32);
        byte[] ke = shake.squeeze(32);

        // Encrypt message
        shake.init(128);
        shake.absorb(ke);
        byte[] keystream = shake.squeeze(message.length);
        byte[] c = new byte[message.length];
        for (int i = 0; i < message.length; i++) {
            c[i] = (byte) (message[i] ^ keystream[i]);
        }

        // Compute authentication tag
        shake.init(256);
        shake.absorb(ka);
        shake.absorb(c);
        byte[] t = shake.digest();

        return new Cryptogram(Z, c, t);
    }

    /**
     * Decrypts a cryptogram using the provided passphrase.
     * <p>
     * This method implements a decryption algorithm based on Edwards curve cryptography
     * and SHA3-SHAKE. It recomputes the private key from the passphrase, verifies the
     * authentication tag, and decrypts the message.
     *
     * @param cryptogram The Cryptogram object containing the encrypted message and associated data.
     * @param passphrase The passphrase used to derive the private key.
     * @return A byte array containing the decrypted message.
     * @throws Exception If authentication fails or any other error occurs during decryption.
     */
    public static byte[] decrypt(Cryptogram cryptogram, String passphrase) throws Exception {
        Edwards E = new Edwards();
        SHA3SHAKE shake = new SHA3SHAKE();
        BigInteger r = CURVE_ORDER_R;

        // Recompute private key
        shake.init(128);
        shake.absorb(passphrase.getBytes());
        byte[] privateKeyBytes = shake.squeeze(32);
        BigInteger s = new BigInteger(1, privateKeyBytes).mod(r);

        // Adjust private key if necessary
        Edwards.Point G = E.gen();
        Edwards.Point V = G.mul(s);
        if (V.getX().testBit(0)) {
            s = r.subtract(s);
        }

        // Compute W
        Edwards.Point W = cryptogram.Z.mul(s);

        // Generate ka and ke
        shake.init(256);
        shake.absorb(W.getY().toByteArray());
        byte[] ka = shake.squeeze(32);
        byte[] ke = shake.squeeze(32);

        // Verify authentication tag
        shake.init(256);
        shake.absorb(ka);
        shake.absorb(cryptogram.c);
        byte[] computedTag = shake.digest();
        if (!Arrays.equals(computedTag, cryptogram.t)) {
            throw new Exception("Authentication tag mismatch");
        }

        // Decrypt message
        shake.init(128);
        shake.absorb(ke);
        byte[] keystream = shake.squeeze(cryptogram.c.length);
        byte[] message = new byte[cryptogram.c.length];
        for (int i = 0; i < cryptogram.c.length; i++) {
            message[i] = (byte) (cryptogram.c[i] ^ keystream[i]);
        }

        return message;
    }

    /**
     * Generates a digital signature for a given message using the Edwards curve.
     * <p></p>
     * This method implements a signature generation algorithm based on the Edwards curve
     * and SHA3-SHAKE hash function. It uses a combination of the private key and a random
     * value to create a signature that can be verified without revealing the private key.
     *
     * @param message The message to be signed, as a byte array.
     * @param s       The private key used for signing, represented as a BigInteger.
     * @return A Signature object containing the components h and z of the generated signature.
     */
    public static Signature generateSignature(byte[] message, BigInteger s) {
        Edwards E = new Edwards();
        BigInteger r = CURVE_ORDER_R;

        // Generate random k
        SecureRandom random = new SecureRandom();
        byte[] kBytes = new byte[32];
        random.nextBytes(kBytes);
        BigInteger k = new BigInteger(1, kBytes).mod(r);

        // Compute U = k * G
        Edwards.Point G = E.gen();
        Edwards.Point U = G.mul(k);

        // Compute h
        SHA3SHAKE sha3 = new SHA3SHAKE();
        sha3.init(256);
        sha3.absorb(U.getY().toByteArray());
        sha3.absorb(message);
        byte[] digest = sha3.digest();
        BigInteger h = new BigInteger(1, digest).mod(r);

        // Compute z
        BigInteger z = k.subtract(h.multiply(s)).mod(r);

        return new Signature(h, z);
    }

    public static boolean verifySignature(byte[] message, Signature signature, Edwards.Point V) {
        BigInteger h = signature.h();
        BigInteger z = signature.z();

        // Compute U' = z * G + h * V
        Edwards E = new Edwards();
        Edwards.Point G = E.gen();
        Edwards.Point UPrime = G.mul(z).add(V.mul(h));

        // Hash the y-coordinate of U' and the message
        SHA3SHAKE sha3 = new SHA3SHAKE();
        sha3.init(256);
        sha3.absorb(UPrime.getY().toByteArray());
        sha3.absorb(message);
        byte[] digest = sha3.digest();

        // Convert the digest to BigInteger and reduce mod r
        BigInteger hPrime = new BigInteger(1, digest).mod(CURVE_ORDER_R);

        // Accept the signature if h' = h
        return hPrime.equals(h);
    }

    //*********************************************************
    //Helper Methods                      *

    /**
     * Represents a key pair for elliptic curve cryptography.
     */
    public record KeyPair(BigInteger privateKey, Edwards.Point publicKey) {
    }

    /**
     * Represents a cryptogram for the ECIES (Elliptic Curve Integrated Encryption Scheme).
     *
     * @param Z The elliptic curve point Z = k * G, where k is the ephemeral private key and G is the curve's generator.
     * @param c The symmetrically encrypted ciphertext.
     * @param t The authentication tag for integrity verification.
     */
    public record Cryptogram(Edwards.Point Z, byte[] c, byte[] t) {
        /**
         * Constructs a new Cryptogram.
         *
         * @param Z The elliptic curve point Z.
         * @param c The encrypted ciphertext.
         * @param t The authentication tag.
         */
        public Cryptogram {
        }
    }

    /**
     * Represents a digital signature in a cryptographic system.
     * <p></p>
     * This class encapsulates two components of a signature:
     * 'h' and 'z', both represented as BigInteger values.
     */
    public record Signature(BigInteger h, BigInteger z) {
    }
}