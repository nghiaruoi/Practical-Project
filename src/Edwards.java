import java.math.BigInteger;

/**
 * Arithmetic on Edwards elliptic curves.
 */
public class Edwards {
    private final BigInteger p; // Field prime
    private final BigInteger d; // Curve coefficient
    private final BigInteger r; // Curve order
    private final Point G; // Generator point

    /**
     * Create an instance of the default curve NUMS-256.
     */
    public Edwards() {
        this.p = BigInteger.TWO.pow(256).subtract(BigInteger.valueOf(189));
        this.d = BigInteger.valueOf(15343);
        this.r = BigInteger.TWO.pow(254).subtract(new BigInteger("87175310462106073678594642380840586067"));
        this.G = findGenerator();
    }

    /**
     * Determine if a given affine coordinate pair P = (x, y)
     * defines a point on the curve.
     *
     * @param x x-coordinate of presumed point on the curve
     * @param y y-coordinate of presumed point on the curve
     * @return whether P is really a point on the curve
     */
    public boolean isPoint(BigInteger x, BigInteger y) {
        BigInteger lhs = x.pow(2).add(y.pow(2)).mod(p);
        BigInteger rhs = BigInteger.ONE.add(d.multiply(x.pow(2)).multiply(y.pow(2))).mod(p);
        return lhs.equals(rhs);
    }

    /**
     * Find a generator G on the curve with the smallest possible
     * y-coordinate in absolute value.
     *
     * @return G.
     */
    public Point gen() {
        return G;
    }

    private Point findGenerator() {
        for (BigInteger y = BigInteger.ONE; y.compareTo(p) < 0; y = y.add(BigInteger.ONE)) {
            Point P = getPoint(y, false);
            if (!P.isZero() && P.mul(r).isZero()) {
                return P;
            }
        }
        throw new RuntimeException("Generator not found");
    }

    /**
     * Create a point from its y-coordinate and
     * the least significant bit (LSB) of its x-coordinate.
     *
     * @param y     the y-coordinate of the desired point
     * @param x_lsb the LSB of its x-coordinate
     * @return point (x, y) if it exists and has order r,
     * otherwise the neutral element O = (0, 1)
     */
    public Point getPoint(BigInteger y, boolean x_lsb) {
        BigInteger y2 = y.multiply(y).mod(p);
        BigInteger numerator = BigInteger.ONE.subtract(y2);
        BigInteger denominator = BigInteger.ONE.subtract(d.multiply(y2));
        BigInteger x2 = numerator.multiply(denominator.modInverse(p)).mod(p);

        BigInteger x = sqrt(x2, p, x_lsb);
        if (x == null) {
            return new Point(); // Return neutral element if sqrt doesn't exist
        }

        Point point = new Point(x, y);
        if (point.mul(r).isZero()) {
            return point;
        } else {
            return new Point(); // Return neutral element if order is not r
        }
    }

    private BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }

    /**
     * Display a human-readable representation of this curve.
     *
     * @return a string of form "E: x^2 + y^2 = 1 + d*x^2*y^2 mod p"
     * where E is a suitable curve name (e.g. NUMS ed-256-mers*),
     * d is the actual curve equation coefficient defining this curve,
     * and p is the order of the underlying finite field F_p.
     */
    @Override
    public String toString() {
        return String.format("NUMS ed-256-mers*: x^2 + y^2 = 1 + %d*x^2*y^2 mod %s", d, p);
    }

    public BigInteger getD() {
        return d;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getOrder() {
        return r;
    }

    /**
     * Edwards curve point in affine coordinates.
     * NB: this is a nested class, enclosed within the Edwards class.
     */
    public class Point {

        private final BigInteger x;
        private final BigInteger y;

        /**
         * Create a copy of the neutral element on this curve.
         */
        public Point() {
            this.x = BigInteger.ZERO;
            this.y = BigInteger.ONE;
        }

        /**
         * Create a point from its coordinates (assuming
         * these coordinates really define a point on the curve).
         *
         * @param x the x-coordinate of the desired point
         * @param y the y-coordinate of the desired point
         */
        private Point(BigInteger x, BigInteger y) {
            if (!isPoint(x, y)) {
                throw new IllegalArgumentException("The point is not on the curve.");
            }
            this.x = x;
            this.y = y;
        }

        /**
         * Determine if this point is the neutral element O on the curve.
         *
         * @return true iff this point is O
         */
        public boolean isZero() {
            return x.equals(BigInteger.ZERO) && y.equals(BigInteger.ONE);
        }

        /**
         * Determine if a given point P stands for
         * the same point on the curve as this.
         *
         * @param P a point (presumably on the same curve as this)
         * @return true iff P stands for the same point as this
         */
        public boolean equals(Point P) {
            return this.x.equals(P.x) && this.y.equals(P.y);
        }

        /**
         * Given a point P = (x, y) on the curve,
         * return its opposite -P = (-x, y).
         *
         * @return -P
         */
        public Point negate() {
            return new Point(x.negate().mod(p), y);
        }

        /**
         * Add two given points on the curve, this and P.
         *
         * @param P a point on the curve
         * @return this + P
         */
        public Point add(Point P) {
            BigInteger x1 = this.x, y1 = this.y;
            BigInteger x2 = P.x, y2 = P.y;

            BigInteger x3Num = x1.multiply(y2).add(y1.multiply(x2)).mod(p);
            BigInteger x3Den = BigInteger.ONE.add(d.multiply(x1).multiply(x2).multiply(y1).multiply(y2)).mod(p);
            BigInteger y3Num = y1.multiply(y2).subtract(x1.multiply(x2)).mod(p);
            BigInteger y3Den = BigInteger.ONE.subtract(d.multiply(x1).multiply(x2).multiply(y1).multiply(y2)).mod(p);

            BigInteger x3 = x3Num.multiply(x3Den.modInverse(p)).mod(p);
            BigInteger y3 = y3Num.multiply(y3Den.modInverse(p)).mod(p);

            return new Point(x3, y3);
        }

        /**
         * Multiply a point P = (x, y) on the curve by a scalar m.
         *
         * @param m a scalar factor (an integer mod the curve order)
         * @return m*P
         */
        public Point mul(BigInteger m) {
            Point result = new Point();
            Point base = this;
            m = m.mod(r);

            while (m.signum() > 0) {
                if (m.testBit(0)) {
                    result = result.add(base);
                }
                base = base.add(base);
                m = m.shiftRight(1);
            }

            return result;
        }

        /**
         * Display a human-readable representation of this point.
         *
         * @return a string of form "(x, y)" where x and y are
         * the coordinates of this point
         */
        @Override
        public String toString() {
            return String.format("(%s, %s)", x.toString(), y.toString());
        }

        public BigInteger getX() {
            return x;
        }

        public BigInteger getY() {
            return y;
        }
    }
}