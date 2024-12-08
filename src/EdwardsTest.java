public static void main(String[] args) {
    try {
        testEdwardsCurveProperties();
        System.out.println("All Edwards curve property tests passed!");
    } catch (AssertionError | IOException e) {
        System.err.println("Test failed: " + e.getMessage());
    }
}

public static void testEdwardsCurveProperties() throws IOException {
    Edwards E = new Edwards();
    Edwards.Point G = E.gen();
    BigInteger r = new BigInteger("2").pow(254).subtract(new BigInteger("87175310462106073678594642380840586067"));

    // Test 0 * G = O
    assert G.mul(BigInteger.ZERO).isZero() : "0 * G should be O";

    // Test 1 * G = G
    assert G.mul(BigInteger.ONE).equals(G) : "1 * G should be G";

    // Test G + (-G) = O
    Edwards.Point negG = G.negate();
    assert G.add(negG).isZero() : "G + (-G) should be O";

    // Test 2 * G = G + G
    assert G.mul(BigInteger.TWO).equals(G.add(G)) : "2 * G should equal G + G";

    // Test 4 * G = 2 * (2 * G)
    Edwards.Point fourG = G.mul(BigInteger.valueOf(4));
    Edwards.Point twoTwoG = G.mul(BigInteger.TWO).mul(BigInteger.TWO);
    assert fourG.equals(twoTwoG) : "4 * G should equal 2 * (2 * G)";

    // Test 4 * G ≠ O
    assert !fourG.isZero() : "4 * G should not be O";

    // Test r * G = O
    assert G.mul(r).isZero() : "r * G should be O";

    // Generate a key pair from a passphrase and test its validity
    String passphrase = "test passphrase";
    String filePath = "./src/public_key.bin";
    EllipticCurve.KeyPair pair = EllipticCurve.generateKeyPair(passphrase);
    BigInteger s = pair.privateKey();
    Edwards.Point V = G.mul(s);

    // Ensure s is within the correct range
    assert s.compareTo(BigInteger.ZERO) > 0 && s.compareTo(r) < 0 : "Private key s should be in range 0 < s < r";

    // Ensure V has the correct order
    assert V.mul(r).isZero() : "V should have order r";

    // Ensure the least significant bit of V's x-coordinate is 0
    BigInteger x = V.getX();
    assert !x.testBit(0) : "LSB of V's x-coordinate should be 0";

    System.out.println("Key pair generation test passed!");
}

private static BigInteger generatePrivateKey(String passphrase) {
    SHA3SHAKE shake = new SHA3SHAKE();
    shake.init(128);
    shake.absorb(passphrase.getBytes());
    byte[] privateKeyBytes = shake.squeeze(32); // 256 bits
    BigInteger s = new BigInteger(1, privateKeyBytes);

    BigInteger r = new BigInteger("2").pow(254).subtract(new BigInteger("87175310462106073678594642380840586067"));

    s = s.mod(r);

    // If LSB of V's x-coordinate is 1, replace s with r - s
    Edwards E = new Edwards();
    Edwards.Point G = E.gen();

    Edwards.Point V = G.mul(s);

    if (V.getX().testBit(0)) {
        s = r.subtract(s);
        V = V.negate(); // Update public key to match adjusted private key
    }

    System.out.println("Private Key: " + s);
    System.out.println("Public Key: " + V.toString());

    return s;
}