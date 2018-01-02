
using System;
using System.Collections;


/**
 * base class for an elliptic curve
 */
namespace Org.BouncyCastle.Math.EC
{
	public abstract class ECCurve
	{
		internal ECFieldElement a, b;

		public abstract ECFieldElement FromBigInteger(BigInteger x);
		public abstract ECPoint DecodePoint(byte[] encoded);
		public abstract ECPoint Infinity { get; }

		public ECFieldElement A
		{
			get { return a; }
		}

		public ECFieldElement B
		{
			get { return b; }
		}

		public override bool Equals(
			object obj)
		{
			if (obj == this)
				return true;

			ECCurve other = obj as ECCurve;

			if (other == null)
				return false;

			return Equals(other);
		}

		protected bool Equals(
			ECCurve other)
		{
			return a.Equals(other.a) && b.Equals(other.b);
		}

		public override int GetHashCode()
		{
			return a.GetHashCode() ^ b.GetHashCode();
		}
	}

	/**
     * Elliptic curve over Fp
     */
    public class FpCurve : ECCurve
    {
        private readonly BigInteger q;
		private readonly FpPoint infinity;

		public FpCurve(BigInteger q, BigInteger a, BigInteger b)
        {
            this.q = q;
            this.a = FromBigInteger(a);
            this.b = FromBigInteger(b);
			this.infinity = new FpPoint(this, null, null);
        }

		public BigInteger Q
        {
			get { return q; }
        }

		public override ECPoint Infinity
		{
			get { return infinity; }
		}

		public override ECFieldElement FromBigInteger(BigInteger x)
        {
            return new FpFieldElement(this.q, x);
        }

        /**
         * Decode a point on this curve from its ASN.1 encoding. The different
         * encodings are taken account of, including point compression for
         * <code>F<sub>p</sub><code> (X9.62 s 4.2.1 pg 17).
         * @return The decoded point.
         */
        public override ECPoint DecodePoint(
			byte[] encoded)
        {
            ECPoint p = null;

            switch (encoded[0])
            {
                // compressed
				case 0x02:
				case 0x03:
					int ytilde = encoded[0] & 1;
					byte[] i = new byte[encoded.Length - 1];

					Array.Copy(encoded, 1, i, 0, i.Length);

					ECFieldElement x = new FpFieldElement(this.q, new BigInteger(1, i));
					ECFieldElement alpha = x.Multiply(x.Square()).Add(x.Multiply(a).Add(b));
					ECFieldElement beta = alpha.Sqrt();

					//
					// if we can't find a sqrt we haven't got a point on the
					// curve - run!
					//
					if (beta == null)
						throw new ArithmeticException("Invalid point compression");

					BigInteger betaValue = beta.ToBigInteger();
					int bit0 = betaValue.TestBit(0) ? 1 : 0;

					if (bit0 != ytilde)
					{
						// Use the other root
						beta = new FpFieldElement(q, q.Subtract(betaValue));
					}

					p = new FpPoint(this, x, beta, true);
					break;
				case 0x04:
					byte[] xEnc = new byte[(encoded.Length - 1) / 2];
					byte[] yEnc = new byte[(encoded.Length - 1) / 2];

					Array.Copy(encoded, 1, xEnc, 0, xEnc.Length);
					Array.Copy(encoded, xEnc.Length + 1, yEnc, 0, yEnc.Length);

					p = new FpPoint(this,
						new FpFieldElement(this.q, new BigInteger(1, xEnc)),
						new FpFieldElement(this.q, new BigInteger(1, yEnc)));
					break;
				default:
					throw new FormatException("Invalid point encoding " + encoded[0]);
            }

			return p;
        }

		public override bool Equals(
            object obj)
        {
            if (obj == this)
                return true;

			FpCurve other = obj as FpCurve;

			if (other == null)
                return false;

			return Equals(other);
        }

		protected bool Equals(
			FpCurve other)
		{
			return base.Equals(other) && q.Equals(other.q);
		}

		public override int GetHashCode()
        {
            return base.GetHashCode() ^ q.GetHashCode();
        }
    }

	/**
     * Elliptic curves over F2m. The Weierstrass equation is given by
     * <code>y<sup>2</sup> + xy = x<sup>3</sup> + ax<sup>2</sup> + b</code>.
     */
    public class F2mCurve : ECCurve
    {
        /**
         * The exponent <code>m</code> of <code>F<sub>2<sup>m</sup></sub></code>.
         */
        private readonly int m;

        /**
         * TPB: The integer <code>k</code> where <code>x<sup>m</sup> +
         * x<sup>k</sup> + 1</code> represents the reduction polynomial
         * <code>f(z)</code>.<br>
         * PPB: The integer <code>k1</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br>
         */
        private readonly int k1;

        /**
         * TPB: Always set to <code>0</code><br>
         * PPB: The integer <code>k2</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br>
         */
        private readonly int k2;

        /**
         * TPB: Always set to <code>0</code><br>
         * PPB: The integer <code>k3</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br>
         */
        private readonly int k3;

		private readonly F2mPoint infinity;

        /**
         * Constructor for Trinomial Polynomial Basis (TPB).
         * @param m  The exponent <code>m</code> of
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param k The integer <code>k</code> where <code>x<sup>m</sup> +
         * x<sup>k</sup> + 1</code> represents the reduction
         * polynomial <code>f(z)</code>.
         * @param a The coefficient <code>a</code> in the Weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param b The coefficient <code>b</code> in the Weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>F<sub>2<sup>m</sup></sub></code>.
         */
        public F2mCurve(
            int m,
            int k,
            BigInteger a,
            BigInteger b) : this(m, k, 0, 0, a, b)
        {
        }

        /**
         * Constructor for Pentanomial Polynomial Basis (PPB).
         * @param m  The exponent <code>m</code> of
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param k1 The integer <code>k1</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.
         * @param k2 The integer <code>k2</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.
         * @param k3 The integer <code>k3</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.
         * @param a The coefficient <code>a</code> in the Weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param b The coefficient <code>b</code> in the Weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>F<sub>2<sup>m</sup></sub></code>.
         */
        public F2mCurve(
            int m,
            int k1,
            int k2,
            int k3,
            BigInteger a,
            BigInteger b)
        {
            this.m = m;
            this.k1 = k1;
            this.k2 = k2;
            this.k3 = k3;
			this.infinity = new F2mPoint(this, null, null);

			if (k1 == 0)
                throw new ArgumentException("k1 must be > 0");

			if (k2 == 0)
            {
                if (k3 != 0)
                    throw new ArgumentException("k3 must be 0 if k2 == 0");
            }
            else
            {
                if (k2 <= k1)
                    throw new ArgumentException("k2 must be > k1");

				if (k3 <= k2)
                    throw new ArgumentException("k3 must be > k2");
            }

			this.a = FromBigInteger(a);
            this.b = FromBigInteger(b);
        }

		public override ECPoint Infinity
		{
			get { return infinity; }
		}

		public override ECFieldElement FromBigInteger(BigInteger x)
        {
            return new F2mFieldElement(this.m, this.k1, this.k2, this.k3, x);
        }

        /* (non-Javadoc)
         * @see Org.BouncyCastle.Math.EC.ECCurve#decodePoint(byte[])
         */
        public override ECPoint DecodePoint(byte[] encoded)
        {
            ECPoint p = null;

            switch (encoded[0])
            {
                // compressed
            case 0x02:
            case 0x03:
                byte[] enc = new byte[encoded.Length - 1];
                Array.Copy(encoded, 1, enc, 0, enc.Length);
                if (encoded[0] == 0x02)
                {
                        p = decompressPoint(enc, 0);
                }
                else
                {
                        p = decompressPoint(enc, 1);
                }
                break;
            case 0x04:
                byte[] xEnc = new byte[(encoded.Length - 1) / 2];
                byte[] yEnc = new byte[(encoded.Length - 1) / 2];

                Array.Copy(encoded, 1, xEnc, 0, xEnc.Length);
                Array.Copy(encoded, xEnc.Length + 1, yEnc, 0, yEnc.Length);

                p = new F2mPoint(this,
                    new F2mFieldElement(this.m, this.k1, this.k2, this.k3,
                        new BigInteger(1, xEnc)),
                    new F2mFieldElement(this.m, this.k1, this.k2, this.k3,
                        new BigInteger(1, yEnc)), false);
                break;

            default:
                throw new FormatException("Invalid point encoding " + encoded[0]);
            }

            return p;
        }

        /**
         * Decompresses a compressed point P = (xp, yp) (X9.62 s 4.2.2).
         *
         * @param xEnc
         *            The encoding of field element xp.
         * @param ypBit
         *            ~yp, an indication bit for the decompression of yp.
         * @return the decompressed point.
         */
        private ECPoint decompressPoint(
            byte[] xEnc,
            int ypBit)
        {
            ECFieldElement xp = new F2mFieldElement(
                    this.m, this.k1, this.k2, this.k3, new BigInteger(1, xEnc));
            ECFieldElement yp = null;
            if (xp.x.SignValue == 0)
            {
                yp = (F2mFieldElement)b;
                for (int i = 0; i < m - 1; i++)
                {
                    yp = yp.Square();
                }
            }
            else
            {
                ECFieldElement beta = xp.Add(a).Add(
                        b.Multiply(xp.Square().Invert()));
                ECFieldElement z = solveQuadradicEquation(beta);
                if (z == null)
                {
                    throw new ArithmeticException("Invalid point compression");
                }
                int zBit = 0;
                if (z.x.TestBit(0))
                {
                    zBit = 1;
                }
                if (zBit != ypBit)
                {
                    z = z.Add(new F2mFieldElement(this.m, this.k1, this.k2,
                            this.k3, BigInteger.One));
                }
                yp = xp.Multiply(z);
            }

            return new F2mPoint(this, xp, yp);
        }

        /**
         * Solves a quadratic equation <code>z<sup>2</sup> + z = beta</code>(X9.62
         * D.1.6) The other solution is <code>z + 1</code>.
         *
         * @param beta
         *            The value to solve the qradratic equation for.
         * @return the solution for <code>z<sup>2</sup> + z = beta</code> or
         *         <code>null</code> if no solution exists.
         */
        private ECFieldElement solveQuadradicEquation(ECFieldElement beta)
        {
            if (beta.x.SignValue == 0)
            {
                return new F2mFieldElement(
                        this.m, this.k1, this.k2, this.k3, BigInteger.Zero);
            }
            ECFieldElement z = null;
            ECFieldElement gamma = new F2mFieldElement(this.m, this.k1,
                    this.k2, this.k3, BigInteger.Zero);
            while (gamma.ToBigInteger().SignValue == 0)
            {
                ECFieldElement t = new F2mFieldElement(this.m, this.k1,
                        this.k2, this.k3, new BigInteger(m, new Random()));
                z = new F2mFieldElement(this.m, this.k1, this.k2, this.k3,
                        BigInteger.Zero);
                ECFieldElement w = beta;
                for (int i = 1; i <= m - 1; i++)
                {
					ECFieldElement w2 = w.Square();
                    z = z.Square().Add(w2.Multiply(t));
                    w = w2.Add(beta);
                }
                if (w.x.SignValue != 0)
                {
                    return null;
                }
                gamma = z.Square().Add(z);
            }
            return z;
        }

		public override bool Equals(
            object obj)
        {
            if (obj == this)
                return true;

			F2mCurve other = obj as F2mCurve;

			if (other == null)
                return false;

			return Equals(other);
        }

		protected bool Equals(
			F2mCurve other)
		{
			return m == other.m
				&& k1 == other.k1
				&& k2 == other.k2
				&& k3 == other.k3
				&& base.Equals(other);
		}

		public override int GetHashCode()
        {
            return base.GetHashCode() ^ m ^ k1 ^ k2 ^ k3;
        }

		public int M
        {
			get { return m; }
        }

		/**
         * Return true if curve uses a Trinomial basis.
         *
         * @return true if curve Trinomial, false otherwise.
         */
        public bool IsTrinomial()
        {
            return k2 == 0 && k3 == 0;
        }

		public int K1
        {
			get { return k1; }
        }

		public int K2
        {
			get { return k2; }
        }

		public int K3
        {
			get { return k3; }
        }
    }
}
