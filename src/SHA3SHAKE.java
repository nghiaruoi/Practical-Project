import java.io.ByteArrayOutputStream;
import java.util.Arrays;

public class SHA3SHAKE {
    private static final int KECCAK_ROUNDS = 24;
    private static final long[] KECCAK_ROUND_CONSTANTS = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };
    private static final int[] KECCAK_ROTATIONS = {
            1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
            27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
    };
    private static final int[] KECCAK_PERMUTATIONS = {
            10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
    };

    private static final byte[] ENCODE_BYTE_TABLE = {
            (byte) '0', (byte) '1', (byte) '2', (byte) '3', (byte) '4', (byte) '5', (byte) '6', (byte) '7',
            (byte) '8', (byte) '9', (byte) 'a', (byte) 'b', (byte) 'c', (byte) 'd', (byte) 'e', (byte) 'f'
    };

    private final long[] state = new long[25];
    private int rateSizeInBytes;
    private int digestSizeInBytes;
    private int position;
    private boolean isSqueezing;

    public SHA3SHAKE() {
    }

    /**
     * Compute the streamlined SHA-3-<224,256,384,512> on input X.
     *
     * @param suffix desired output length in bits (one of 224, 256, 384, 512)
     * @param X      data to be hashed
     * @param out    hash value buffer (if null, this method allocates it with the required size)
     * @return the out buffer containing the desired hash value.
     */
    public static byte[] SHA3(int suffix, byte[] X, byte[] out) {
        SHA3SHAKE sha3 = new SHA3SHAKE();
        sha3.init(suffix);
        sha3.absorb(X);

        if (out == null || out.length < suffix / 8) {
            out = new byte[suffix / 8];
        }

        return sha3.digest(out);
    }

    /**
     * Compute the streamlined SHAKE-<128,256> on input X with output bitlength L.
     *
     * @param suffix desired security level (either 128 or 256)
     * @param X      data to be hashed
     * @param L      desired output length in bits (must be a multiple of 8)
     * @param out    hash value buffer (if null, this method allocates it with the required size)
     * @return the out buffer containing the desired hash value.
     */
    public static byte[] SHAKE(int suffix, byte[] X, int L, byte[] out) {
        if (suffix != 128 && suffix != 256) {
            throw new IllegalArgumentException("SHAKE suffix must be either 128 or 256");
        }
        if (L % 8 != 0) {
            throw new IllegalArgumentException("Output length L must be a multiple of 8 bits");
        }

        SHA3SHAKE shake = new SHA3SHAKE();
        shake.init(suffix);
        shake.absorb(X);

        int outputBytes = L / 8;
        if (out == null || out.length < outputBytes) {
            out = new byte[outputBytes];
        }

        return shake.squeeze(out, outputBytes);
    }

    /**
     * Compute MAC
     */
    public static void MAC(byte[] fileContent, String passphrase, int outputLength) {
        byte[] passphraseBytes = passphrase.getBytes();
        SHA3SHAKE shake128 = new SHA3SHAKE();
        shake128.init(128);
        shake128.absorb(passphraseBytes);
        shake128.absorb(fileContent);
        shake128.absorb("T".getBytes());
        byte[] mac128 = shake128.squeeze(outputLength / 8);

        SHA3SHAKE shake256 = new SHA3SHAKE();
        shake256.init(256);
        shake256.absorb(passphraseBytes);
        shake256.absorb(fileContent);
        shake256.absorb("T".getBytes());
        byte[] mac256 = shake256.squeeze(outputLength / 8);

        System.out.println("SHAKE128 MAC: " + convertBytesToString(mac128));
        System.out.println("SHAKE256 MAC: " + convertBytesToString(mac256));
    }

    /**
     * Convert bytes to string.
     *
     * @param data bytes array
     * @return string
     */
    public static String convertBytesToString(final byte[] data) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        for (byte datum : data) {
            int uVal = datum & 0xFF;

            buffer.write(ENCODE_BYTE_TABLE[(uVal >>> 4)]);
            buffer.write(ENCODE_BYTE_TABLE[uVal & 0xF]);
        }

        return buffer.toString();
    }

    /**
     * Initialize the SHA-3/SHAKE sponge.
     * The suffix must be one of 224, 256, 384, or 512 for SHA-3, or one of 128 or 256 for SHAKE.
     *
     * @param suffix SHA-3/SHAKE suffix (SHA-3 digest bitlength = suffix, SHAKE sec level = suffix)
     */
    public void init(int suffix) {
        Arrays.fill(state, 0L);
        this.position = 0;
        this.isSqueezing = false;
        this.rateSizeInBytes = 200 - (suffix / 4);
        this.digestSizeInBytes = suffix / 8;
    }

    /**
     * Update the SHAKE sponge with a byte-oriented data chunk.
     *
     * @param data byte-oriented data buffer
     */
    public void absorb(byte[] data) {
        absorb(data, 0, data.length);
    }

    /**
     * Update the SHAKE sponge with a byte-oriented data chunk.
     *
     * @param data byte-oriented data buffer
     * @param len  byte count on the buffer (starting at index 0)
     */
    public void absorb(byte[] data, int len) {
        absorb(data, 0, len);
    }

    /**
     * Update the SHAKE sponge with a byte-oriented data chunk.
     *
     * @param data byte-oriented data buffer
     * @param pos  initial index to hash from
     * @param len  byte count on the buffer
     */
    public void absorb(byte[] data, int pos, int len) {
        for (int i = pos; i < pos + len; i++) {
            state[position / 8] ^= ((long) data[i] & 0xFF) << (8 * (position % 8));
            position++;
            if (position == rateSizeInBytes) {
                keccakF1600();
                position = 0;
            }
        }
    }

    /**
     * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
     *
     * @return the desired hash value on a newly allocated byte array
     */
    public byte[] digest() {
        return digest(new byte[digestSizeInBytes]);
    }

    /**
     * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
     *
     * @param out hash value buffer
     * @return the val buffer containing the desired hash value
     */
    public byte[] digest(byte[] out) {

        // Padding
        state[position / 8] ^= 0x06L << (8 * (position % 8));
        state[(rateSizeInBytes - 1) / 8] ^= 0x80L << (8 * ((rateSizeInBytes - 1) % 8));
        keccakF1600();

        // Extract the digest
        for (int i = 0; i < digestSizeInBytes; i++) {
            out[i] = (byte) (state[i / 8] >> (8 * (i % 8)));
        }

        return out;
    }

    /**
     * Squeeze a chunk of hashed bytes from the sponge.
     * Call this method as many times as needed to extract the total desired number of bytes.*
     *
     * @param len desired number of squeezed bytes
     * @return newly allocated buffer containing the desired hash value
     */
    public byte[] squeeze(int len) {
        return squeeze(new byte[len], len);
    }

    /**
     * Squeeze a chunk of hashed bytes from the sponge.
     * Call this method as many times as needed to extract the total desired number of bytes.*
     *
     * @param len desired number of squeezed bytes
     * @return newly allocated buffer containing the desired hash value
     */
    public byte[] squeeze(byte[] out, int len) {
        if (!isSqueezing) {
            state[position / 8] ^= 0x1FL << (8 * (position % 8));
            state[(rateSizeInBytes - 1) / 8] ^= 0x80L << (8 * ((rateSizeInBytes - 1) % 8));
            keccakF1600();
            position = 0;
            isSqueezing = true;
        }

        for (int i = 0; i < len; i++) {
            if (position == rateSizeInBytes) {
                keccakF1600();
                position = 0;
            }
            out[i] = (byte) (state[position / 8] >> (8 * (position % 8)));
            position++;
        }

        return out;
    }

    /**
     * Perform the Keccak-f[1600] permutation
     */
    private void keccakF1600() {
        long[] lanes = new long[5];
        long temp;

        for (int round = 0; round < KECCAK_ROUNDS; round++) {
            // Theta step
            for (int x = 0; x < 5; x++) {
                lanes[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            }
            for (int x = 0; x < 5; x++) {
                temp = lanes[(x + 4) % 5] ^ Long.rotateLeft(lanes[(x + 1) % 5], 1);
                for (int y = 0; y < 25; y += 5) {
                    state[y + x] ^= temp;
                }
            }

            // Rho and Pi steps
            temp = state[1];
            for (int i = 0; i < 24; i++) {
                int j = KECCAK_PERMUTATIONS[i];
                lanes[0] = state[j];
                state[j] = Long.rotateLeft(temp, KECCAK_ROTATIONS[i]);
                temp = lanes[0];
            }

            // Chi step
            for (int y = 0; y < 25; y += 5) {
                System.arraycopy(state, y, lanes, 0, 5);
                for (int x = 0; x < 5; x++) {
                    state[y + x] ^= (~lanes[(x + 1) % 5]) & lanes[(x + 2) % 5];
                }
            }

            // Iota step
            state[0] ^= KECCAK_ROUND_CONSTANTS[round];
        }
    }
}