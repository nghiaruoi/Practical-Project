import java.math.BigInteger;
import java.util.Arrays;

import static java.lang.Math.min;
import static java.lang.System.arraycopy;
import static java.util.Arrays.fill;

public class SHA3SHAKE {

    private static final int STATE_SIZE = 200;
    private static int[] state = new int[STATE_SIZE];
    private static int rateInBits;     // The rate in bits
    private int capacity; // The capacity in bits
    private static int domainSep;
    private static int currentPosition;

    public SHA3SHAKE() {
        state = new int[STATE_SIZE];
    }
private static BigInteger BIT_64 = new BigInteger("18446744073709551615");
    /**
     * Compute the streamlined SHA-3-<224,256,384,512> on input X.
     *
     * @param suffix desired output length in bits (one of 224, 256, 384, 512)
     * @param X      data to be hashed
     * @param out    hash value buffer (if null, this method allocates it with the required size)
     * @return the out buffer containing the desired hash value.
     */
    public static byte[] SHA3(int suffix, byte[] X, byte[] out) {
        byte[] data = X.clone();
        domainSep = 0x06;
        SHA3SHAKE sha3 = new SHA3SHAKE();
        sha3.init(suffix);
        sha3.absorb(data);
        padding();
        return sha3.squeeze(out, suffix / 8);
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
        byte[] data = X.clone();
        domainSep = 0x1F;
        SHA3SHAKE shake = new SHA3SHAKE();
        shake.init(suffix);
        shake.absorb(data);
        return shake.squeeze(out, L / 8);
    }

    public static void MAC(byte[] fileContent, String passphrase, int outputLength) {
        byte[] passphraseBytes = passphrase.getBytes();
        domainSep = 0x1F;
        SHA3SHAKE shake128 = new SHA3SHAKE();
        shake128.init(128);
        shake128.absorb(passphraseBytes);
        shake128.absorb(fileContent);

        shake128.absorb("T".getBytes());
        padding();
        byte[] mac128 = shake128.squeeze(256 / 8);

        SHA3SHAKE shake256 = new SHA3SHAKE();
        shake256.init(256);
        shake256.absorb(passphraseBytes);
        shake256.absorb(fileContent);

        shake256.absorb("T".getBytes());
        padding();
        byte[] mac256 = shake256.squeeze(outputLength / 8);

        System.out.println("SHAKE128 MAC: " + HexUtils.convertBytesToString(mac128));
        System.out.println("SHAKE256 MAC: " + HexUtils.convertBytesToString(mac256));
    }


    /**
     * Initialize the SHA-3/SHAKE sponge.
     * The suffix must be one of 224, 256, 384, or 512 for SHA-3, or one of 128 or 256 for SHAKE.
     * Reference: https://keccak.team/keccak_specs_summary.html
     *
     * @param suffix SHA-3/SHAKE suffix (SHA-3 digest bitlength = suffix, SHAKE sec level = suffix)
     */
    public void init(int suffix) {

        // Set the rate and capacity based on the suffix
        switch (suffix) {
            case 224:
                rateInBits = 1152;
                break;
            case 256:
                rateInBits = 1088;
                break;
            case 384:
                rateInBits = 832;
                break;
            case 512:
                rateInBits = 576;
                break;
            case 128:
                rateInBits = 1344;
                domainSep = 0x1F;
                break;
            default:
                throw new IllegalArgumentException("Invalid suffix. Must be 224, 256, 384, or 512 for SHA-3, or 128 or 256 for SHAKE.");
        }
        capacity = STATE_SIZE * 8 - rateInBits;
        Arrays.fill(state, 0);
    }


    /**
     * Update the SHAKE sponge with a byte-oriented data chunk.
     *
     * @param data byte-oriented data buffer
     * @param pos  initial index to hash from
     * @param len  byte count on the buffer
     */
    public void absorb(byte[] data, int pos, int len) {
        int[] convertedData = HexUtils.convertToUnsignedInt(data);
        int rateInBytes = rateInBits / 8;
        int blockSize;
        int remainingLength = len;

        // Absorbing phase
        while (remainingLength > 0) {
            blockSize = Math.min(remainingLength, rateInBytes);
            for (int i = 0; i < blockSize; i++) {
                state[i] ^= convertedData[i + pos];
            }

            pos += blockSize;
            remainingLength -= blockSize;

            if (blockSize == rateInBytes) {
                keccakf1600(state);
            }
        }
        currentPosition = pos;
//        // Padding phase
//        blockSize = pos % rateInBytes;  // Get the size of the last block
//
//        // Apply domain separation padding
//        state[blockSize] ^= domainSep;
//        if ((domainSep & 0x80) != 0 && blockSize == (rateInBytes - 1)) {
//            keccakf1600(state);
//        }
//
//        // Apply end of message padding
//        state[rateInBytes - 1] ^= 0x80;
//
//        // Final permutation
//        keccakf1600(state);
    }
    private static void padding() {
        int rateInBytes = rateInBits / 8;
        int blockSize = currentPosition % rateInBytes;  // Get the size of the last block

        // Apply domain separation padding
        state[blockSize] ^= domainSep;
        if ((domainSep & 0x80) != 0 && blockSize == (rateInBytes - 1)) {
            keccakf1600(state);
        }

        // Apply end of message padding
        state[rateInBytes - 1] ^= 0x80;

        // Final permutation
        keccakf1600(state);

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
     */
    public void absorb(byte[] data) {
        absorb(data, 0, data.length);
    }

    /**
     * Squeeze a chunk of hashed bytes from the sponge.
     * Call this method as many times as needed to extract the total desired number of bytes.
     *
     * @param out hash value buffer
     * @param len desired number of squeezed bytes
     * @return the val buffer containing the desired hash value
     */
    public byte[] squeeze(byte[] out, int len) {
        if (out == null) {
            out = new byte[len];
        }
        int rateInBytes = rateInBits / 8;
        int blockSize;
        int remainingLength = len;
        int outOffset = 0;

        while (remainingLength > 0) {
            blockSize = Math.min(remainingLength, rateInBytes);
            for (int i = 0; i < blockSize; i++) {
                out[outOffset + i] = (byte) state[i];
            }

            outOffset += blockSize;
            remainingLength -= blockSize;

            if (remainingLength > 0) {
                keccakf1600(state);
            }
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
     * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
     *
     * @param out hash value buffer
     * @return the val buffer containing the desired hash value
     */
    public byte[] digest(byte[] out) {
        int digestSize = (capacity / 2) / 8;
        if (out == null) {
            out = new byte[digestSize];
        }
        // Padding
        state[rateInBits / 8] ^= 0x06;
        state[199] ^= 0x80;
        keccakf1600(state);
        return squeeze(out, digestSize);
    }

    /**
     * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
     *
     * @return the desired hash value on a newly allocated byte array
     */
    public byte[] digest() {
        return digest(new byte[capacity / 16]);
    }

    private static void keccakf1600(final int[] uState) {
        BigInteger[][] lState = new BigInteger[5][5];

        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                int[] data = new int[8];
                arraycopy(uState, 8 * (i + 5 * j), data, 0, data.length);
                lState[i][j] = HexUtils.convertFromLittleEndianTo64(data);
            }
        }
        roundB(lState);

        fill(uState, 0);
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                int[] data = HexUtils.convertFrom64ToLittleEndian(lState[i][j]);
                arraycopy(data, 0, uState, 8 * (i + 5 * j), data.length);
            }
        }

    }

    /**
     * Permutation on the given state.
     *
     * @param state state
     */
    private static void roundB(final BigInteger[][] state) {
        int LFSRstate = 1;
        for (int round = 0; round < 24; round++) {
            BigInteger[] C = new BigInteger[5];
            BigInteger[] D = new BigInteger[5];

            // θ step
            for (int i = 0; i < 5; i++) {
                C[i] = state[i][0].xor(state[i][1]).xor(state[i][2]).xor(state[i][3]).xor(state[i][4]);
            }

            for (int i = 0; i < 5; i++) {
                D[i] = C[(i + 4) % 5].xor(HexUtils.leftRotate64(C[(i + 1) % 5], 1));
            }

            for (int i = 0; i < 5; i++) {
                for (int j = 0; j < 5; j++) {
                    state[i][j] = state[i][j].xor(D[i]);
                }
            }

            //ρ and π steps
            int x = 1, y = 0;
            BigInteger current = state[x][y];
            for (int i = 0; i < 24; i++) {
                int tX = x;
                x = y;
                y = (2 * tX + 3 * y) % 5;

                BigInteger shiftValue = current;
                current = state[x][y];

                state[x][y] = HexUtils.leftRotate64(shiftValue, (i + 1) * (i + 2) / 2);
            }

            //χ step
            for (int j = 0; j < 5; j++) {
                BigInteger[] t = new BigInteger[5];
                for (int i = 0; i < 5; i++) {
                    t[i] = state[i][j];
                }

                for (int i = 0; i < 5; i++) {
                    // ~t[(i + 1) % 5]
                    BigInteger invertVal = t[(i + 1) % 5].xor(BIT_64);
                    // t[i] ^ ((~t[(i + 1) % 5]) & t[(i + 2) % 5])
                    state[i][j] = t[i].xor(invertVal.and(t[(i + 2) % 5]));
                }
            }

            //ι step
            for (int i = 0; i < 7; i++) {
                LFSRstate = ((LFSRstate << 1) ^ ((LFSRstate >> 7) * 0x71)) % 256;
                // pow(2, i) - 1
                int bitPosition = (1 << i) - 1;
                if ((LFSRstate & 2) != 0) {
                    state[0][0] = state[0][0].xor(new BigInteger("1").shiftLeft(bitPosition));
                }
            }
        }
    }
}
