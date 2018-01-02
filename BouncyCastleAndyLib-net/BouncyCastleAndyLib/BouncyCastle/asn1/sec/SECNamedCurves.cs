using System;
using System.Collections;
using System.Globalization;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1.Sec
{
	public sealed class SecNamedCurves
	{
		private SecNamedCurves()
		{
		}

		/*
		 * secp224r1 (NIST P-224)
		 */
		// p = 2^224 - 2^96 + 1
		static readonly BigInteger secp224r1P = new BigInteger(
			"26959946667150639794667015087019630673557916260026308143510066298881");

		// a = -3, b = b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4
		static readonly ECCurve secp224r1Curve = new FpCurve(secp224r1P,
			new BigInteger("26959946667150639794667015087019630673557916260026308143510066298878"),
			new BigInteger("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", 16));

		// x = b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21
		static readonly ECFieldElement secp224r1x = new FpFieldElement(
			secp224r1P,
			new BigInteger("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21", 16));

		// y = bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34
		static readonly ECFieldElement secp224r1y = new FpFieldElement(
			secp224r1P,
			new BigInteger("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34", 16));

		static readonly ECPoint secp224r1BasePoint = new FpPoint(
			secp224r1Curve, secp224r1x, secp224r1y, false);

		static readonly BigInteger secp224r1n = new BigInteger("26959946667150639794667015087019625940457807714424391721682722368061");

		static readonly BigInteger secp224r1h = new BigInteger("1");

		//static readonly byte[] secp224r1Seed = (Hex.decode("bd71344799d5c7fcdc45b59fa3b9ab8f6a948bc5"));
		private const byte[] secp224r1Seed = null;

		static readonly X9ECParameters secp224r1 = new X9ECParameters(
			secp224r1Curve,
			secp224r1BasePoint,
			secp224r1n,
			secp224r1h,
			secp224r1Seed);

		/*
		 * secp256r1 (NIST P-256)
		 */
		// p = 2^256 - 2^224 + 2^192 + 2^96 - 1
		static readonly BigInteger secp256r1P = new BigInteger(
			"115792089210356248762697446949407573530086143415290314195533631308867097853951");

		// a = -3, b = 5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
		static readonly ECCurve secp256r1Curve = new FpCurve(secp256r1P,
			new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948"),
			new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16));

		// x = 6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
		static readonly ECFieldElement secp256r1x = new FpFieldElement(
			secp256r1P,
			new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16));

		// y = 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
		static readonly ECFieldElement secp256r1y = new FpFieldElement(
			secp256r1P,
			new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16));

		static readonly ECPoint secp256r1BasePoint = new FpPoint(
			secp256r1Curve, secp256r1x, secp256r1y, false);

		static readonly BigInteger secp256r1n = new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369");

		static readonly BigInteger secp256r1h = new BigInteger("1");

		//static readonly byte[] secp256r1Seed = (Hex.decode("c49d360886e704936a6678e1139d26b7819f7e90"));
		private const byte[] secp256r1Seed = null;

		static readonly X9ECParameters secp256r1 = new X9ECParameters(
			secp256r1Curve,
			secp256r1BasePoint,
			secp256r1n,
			secp256r1h,
			secp256r1Seed);

		/*
		 * secp384r1 (NIST P-384)
		 */
		// p = 2^384 - 2^128 - 2^96 + 2^32 - 1

		static readonly BigInteger secp384r1P = new BigInteger(
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", 16);

		// a, b
		static readonly ECCurve secp384r1Curve = new FpCurve(secp384r1P,
			new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", 16),
			new BigInteger("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", 16));

		// x
		static readonly ECFieldElement secp384r1x = new FpFieldElement(
			secp384r1P,
			new BigInteger("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", 16));

		// y
		static readonly ECFieldElement secp384r1y = new FpFieldElement(
			secp384r1P,
			new BigInteger("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", 16));

		static readonly ECPoint secp384r1BasePoint = new FpPoint(
			secp384r1Curve, secp384r1x, secp384r1y, false);

		static readonly BigInteger secp384r1n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16);

		static readonly BigInteger secp384r1h = BigInteger.One;

		//static readonly byte[] secp384r1Seed = (Hex.decode("A335926AA319A27A1D00896A6773A4827ACDAC73"));
		static readonly byte[] secp384r1Seed = null;

		static readonly X9ECParameters secp384r1 = new X9ECParameters(
													secp384r1Curve,
													secp384r1BasePoint,
													secp384r1n,
													secp384r1h,
													secp384r1Seed);

		/*
		 * secp521r1 - (NIST P-521)
		 */
		// p = 2^521 - 1
		static readonly BigInteger secp521r1P = new BigInteger(
			"6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151");

		// a = -3, b = 051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00
		static readonly ECCurve secp521r1Curve = new FpCurve(secp521r1P,
			new BigInteger("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057148"),
			new BigInteger("051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16));

		// x = c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66
		static readonly ECFieldElement secp521r1x = new FpFieldElement(
			secp521r1P,
			new BigInteger("c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16));

		// y = 11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650
		static readonly ECFieldElement secp521r1y = new FpFieldElement(
			secp521r1P,
			new BigInteger("11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16));

		static readonly ECPoint secp521r1BasePoint = new FpPoint(
			secp521r1Curve, secp521r1x, secp521r1y, false);

		static readonly BigInteger secp521r1n = new BigInteger("6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449");

		static readonly BigInteger secp521r1h = new BigInteger("1");

		//static readonly byte[] secp521r1Seed = (Hex.decode("d09e8800291cb85396cc6717393284aaa0da64ba"));
		private const byte[] secp521r1Seed = null;

		static readonly X9ECParameters secp521r1 = new X9ECParameters(
			secp521r1Curve,
			secp521r1BasePoint,
			secp521r1n,
			secp521r1h,
			secp521r1Seed);

		/*
		 * sect163r2 (NIST B-163)
		 */
		// m = 163, k1 = 3, k2 = 6, k3 = 7
		const int sect163r2m = 163;
		const int sect163r2k1 = 3;
		const int sect163r2k2 = 6;
		const int sect163r2k3 = 7;

		// a = 1
		static readonly BigInteger sect163r2a = BigInteger.One;

		// b = 20a601907b8c953ca1481eb10512f78744a3205fd
		static readonly BigInteger sect163r2b = new BigInteger("20a601907b8c953ca1481eb10512f78744a3205fd", 16);

		static readonly ECCurve sect163r2Curve = new F2mCurve(sect163r2m, sect163r2k1, sect163r2k2, sect163r2k3, sect163r2a, sect163r2b);

		// x = 3f0eba16286a2d57ea0991168d4994637e8343e36
		static readonly ECFieldElement sect163r2x = new F2mFieldElement(
			sect163r2m, sect163r2k1, sect163r2k2, sect163r2k3,
			new BigInteger("3f0eba16286a2d57ea0991168d4994637e8343e36", 16));

		// y = 0d51fbc6c71a0094fa2cdd545b11c5c0c797324f1
		static readonly ECFieldElement sect163r2y = new F2mFieldElement(
			sect163r2m, sect163r2k1, sect163r2k2, sect163r2k3,
			new BigInteger("0d51fbc6c71a0094fa2cdd545b11c5c0c797324f1", 16));

		static readonly ECPoint sect163r2BasePoint = new F2mPoint(
			sect163r2Curve, sect163r2x, sect163r2y, false);

		static readonly BigInteger sect163r2n = new BigInteger("5846006549323611672814742442876390689256843201587");

		static readonly BigInteger sect163r2h = BigInteger.Two;

		private const byte[] sect163r2Seed = null;

		static readonly X9ECParameters sect163r2 = new X9ECParameters(
			sect163r2Curve,
			sect163r2BasePoint,
			sect163r2n,
			sect163r2h,
			sect163r2Seed);

		/*
		 * sect233r1 (NIST B-233)
		 */
		// m = 233, k1 = 74, k2 = 0, k3 = 0
		const int sect233r1m = 233;
		const int sect233r1k1 = 74;
		const int sect233r1k2 = 0;
		const int sect233r1k3 = 0;

		// a = 1
		static readonly BigInteger sect233r1a = BigInteger.One;

		// b = 066647ede6c332c7f8c0923bb58213b333b20e9ce4281fe115f7d8f90ad
		static readonly BigInteger sect233r1b = new BigInteger("066647ede6c332c7f8c0923bb58213b333b20e9ce4281fe115f7d8f90ad", 16);

		static readonly ECCurve sect233r1Curve = new F2mCurve(sect233r1m, sect233r1k1, sect233r1k2, sect233r1k3, sect233r1a, sect233r1b);

		// x = 0fac9dfcbac8313bb2139f1bb755fef65bc391f8b36f8f8eb7371fd558b
		static readonly ECFieldElement sect233r1x = new F2mFieldElement(
			sect233r1m, sect233r1k1, sect233r1k2, sect233r1k3,
			new BigInteger("0fac9dfcbac8313bb2139f1bb755fef65bc391f8b36f8f8eb7371fd558b", 16));

		// y = 1006a08a41903350678e58528bebf8a0beff867a7ca36716f7e01f81052
		static readonly ECFieldElement sect233r1y = new F2mFieldElement(
			sect233r1m, sect233r1k1, sect233r1k2, sect233r1k3,
			new BigInteger("1006a08a41903350678e58528bebf8a0beff867a7ca36716f7e01f81052", 16));

		static readonly ECPoint sect233r1BasePoint = new F2mPoint(
			sect233r1Curve, sect233r1x, sect233r1y, false);

		static readonly BigInteger sect233r1n = new BigInteger("6901746346790563787434755862277025555839812737345013555379383634485463");

		static readonly BigInteger sect233r1h = BigInteger.Two;

		private const byte[] sect233r1Seed = null;

		static readonly X9ECParameters sect233r1 = new X9ECParameters(
			sect233r1Curve,
			sect233r1BasePoint,
			sect233r1n,
			sect233r1h,
			sect233r1Seed);


		/*
		 * sect283r1 (NIST B-283)
		 */
		// m = 283, k1 = 5, k2 = 7, k3 = 12
		const int sect283r1m = 283;
		const int sect283r1k1 = 5;
		const int sect283r1k2 = 7;
		const int sect283r1k3 = 12;

		// a = 1
		static readonly BigInteger sect283r1a = BigInteger.One;

		// b = 27b680ac8b8596da5a4af8a19a0303fca97fd7645309fa2a581485af6263e313b79a2f5
		static readonly BigInteger sect283r1b = new BigInteger("27b680ac8b8596da5a4af8a19a0303fca97fd7645309fa2a581485af6263e313b79a2f5", 16);

		static readonly ECCurve sect283r1Curve = new F2mCurve(sect283r1m, sect283r1k1, sect283r1k2, sect283r1k3, sect283r1a, sect283r1b);

		// x = 5f939258db7dd90e1934f8c70b0dfec2eed25b8557eac9c80e2e198f8cdbecd86b12053
		static readonly ECFieldElement sect283r1x = new F2mFieldElement(
			sect283r1m, sect283r1k1, sect283r1k2, sect283r1k3,
			new BigInteger("5f939258db7dd90e1934f8c70b0dfec2eed25b8557eac9c80e2e198f8cdbecd86b12053", 16));

		// y = 3676854fe24141cb98fe6d4b20d02b4516ff702350eddb0826779c813f0df45be8112f4
		static readonly ECFieldElement sect283r1y = new F2mFieldElement(
			sect283r1m, sect283r1k1, sect283r1k2, sect283r1k3,
			new BigInteger("3676854fe24141cb98fe6d4b20d02b4516ff702350eddb0826779c813f0df45be8112f4", 16));

		static readonly ECPoint sect283r1BasePoint = new F2mPoint(
			sect283r1Curve, sect283r1x, sect283r1y, false);

		static readonly BigInteger sect283r1n = new BigInteger("7770675568902916283677847627294075626569625924376904889109196526770044277787378692871");

		static readonly BigInteger sect283r1h = BigInteger.Two;

		private const byte[] sect283r1Seed = null;

		static readonly X9ECParameters sect283r1 = new X9ECParameters(
			sect283r1Curve,
			sect283r1BasePoint,
			sect283r1n,
			sect283r1h,
			sect283r1Seed);


		/*
		 * sect409r1 (NIST - B-409)
		 */
		// m = 409, k1 = 87, k2 = 0, k3 = 0
		const int sect409r1m = 409;
		const int sect409r1k1 = 87;
		const int sect409r1k2 = 0;
		const int sect409r1k3 = 0;

		// a = 1
		static readonly BigInteger sect409r1a = BigInteger.One;

		// b = 21a5c2c8ee9feb5c4b9a753b7b476b7fd6422ef1f3dd674761fa99d6ac27c8a9a197b272822f6cd57a55aa4f50ae317b13545f
		static readonly BigInteger sect409r1b = new BigInteger("21a5c2c8ee9feb5c4b9a753b7b476b7fd6422ef1f3dd674761fa99d6ac27c8a9a197b272822f6cd57a55aa4f50ae317b13545f", 16);

		static readonly ECCurve sect409r1Curve = new F2mCurve(sect409r1m, sect409r1k1, sect409r1k2, sect409r1k3, sect409r1a, sect409r1b);

		// x = 15d4860d088ddb3496b0c6064756260441cde4af1771d4db01ffe5b34e59703dc255a868a1180515603aeab60794e54bb7996a7
		static readonly ECFieldElement sect409r1x = new F2mFieldElement(
			sect409r1m, sect409r1k1, sect409r1k2, sect409r1k3,
			new BigInteger("15d4860d088ddb3496b0c6064756260441cde4af1771d4db01ffe5b34e59703dc255a868a1180515603aeab60794e54bb7996a7", 16));

		// y = 61b1cfab6be5f32bbfa78324ed106a7636b9c5a7bd198d0158aa4f5488d08f38514f1fdf4b4f40d2181b3681c364ba0273c706
		static readonly ECFieldElement sect409r1y = new F2mFieldElement(
			sect409r1m, sect409r1k1, sect409r1k2, sect409r1k3,
			new BigInteger("61b1cfab6be5f32bbfa78324ed106a7636b9c5a7bd198d0158aa4f5488d08f38514f1fdf4b4f40d2181b3681c364ba0273c706", 16));

		static readonly ECPoint sect409r1BasePoint = new F2mPoint(
			sect409r1Curve, sect409r1x, sect409r1y, false);

		static readonly BigInteger sect409r1n = new BigInteger("661055968790248598951915308032771039828404682964281219284648798304157774827374805208143723762179110965979867288366567526771");

		static readonly BigInteger sect409r1h = BigInteger.Two;

		private const byte[] sect409r1Seed = null;

		static readonly X9ECParameters sect409r1 = new X9ECParameters(
			sect409r1Curve,
			sect409r1BasePoint,
			sect409r1n,
			sect409r1h,
			sect409r1Seed);


		/*
		 * sect571r1 (NIST - B-571)
		 */
		// m = 571, k1 = 2, k2 = 5, k3 = 10
		const int sect571r1m = 571;
		const int sect571r1k1 = 2;
		const int sect571r1k2 = 5;
		const int sect571r1k3 = 10;

		// a = 1
		static readonly BigInteger sect571r1a = BigInteger.One;

		// b = 2f40e7e2221f295de297117b7f3d62f5c6a97ffcb8ceff1cd6ba8ce4a9a18ad84ffabbd8efa59332be7ad6756a66e294afd185a78ff12aa520e4de739baca0c7ffeff7f2955727a
		static readonly BigInteger sect571r1b = new BigInteger("2f40e7e2221f295de297117b7f3d62f5c6a97ffcb8ceff1cd6ba8ce4a9a18ad84ffabbd8efa59332be7ad6756a66e294afd185a78ff12aa520e4de739baca0c7ffeff7f2955727a", 16);

		static readonly ECCurve sect571r1Curve = new F2mCurve(sect571r1m, sect571r1k1, sect571r1k2, sect571r1k3, sect571r1a, sect571r1b);

		// x = 303001d34b856296c16c0d40d3cd7750a93d1d2955fa80aa5f40fc8db7b2abdbde53950f4c0d293cdd711a35b67fb1499ae60038614f1394abfa3b4c850d927e1e7769c8eec2d19
		static readonly ECFieldElement sect571r1x = new F2mFieldElement(
			sect571r1m, sect571r1k1, sect571r1k2, sect571r1k3,
			new BigInteger("303001d34b856296c16c0d40d3cd7750a93d1d2955fa80aa5f40fc8db7b2abdbde53950f4c0d293cdd711a35b67fb1499ae60038614f1394abfa3b4c850d927e1e7769c8eec2d19", 16));

		// y = 37bf27342da639b6dccfffeb73d69d78c6c27a6009cbbca1980f8533921e8a684423e43bab08a576291af8f461bb2a8b3531d2f0485c19b16e2f1516e23dd3c1a4827af1b8ac15b
		static readonly ECFieldElement sect571r1y = new F2mFieldElement(
			sect571r1m, sect571r1k1, sect571r1k2, sect571r1k3,
			new BigInteger("37bf27342da639b6dccfffeb73d69d78c6c27a6009cbbca1980f8533921e8a684423e43bab08a576291af8f461bb2a8b3531d2f0485c19b16e2f1516e23dd3c1a4827af1b8ac15b", 16));

		static readonly ECPoint sect571r1BasePoint = new F2mPoint(
			sect571r1Curve, sect571r1x, sect571r1y, false);

		static readonly BigInteger sect571r1n = new BigInteger("3864537523017258344695351890931987344298927329706434998657235251451519142289560424536143999389415773083133881121926944486246872462816813070234528288303332411393191105285703");

		static readonly BigInteger sect571r1h = BigInteger.Two;

		private const byte[] sect571r1Seed = null;

		static readonly X9ECParameters sect571r1 = new X9ECParameters(
			sect571r1Curve,
			sect571r1BasePoint,
			sect571r1n,
			sect571r1h,
			sect571r1Seed);


		static readonly Hashtable objIds = new Hashtable();
		static readonly Hashtable curves = new Hashtable();
		static readonly Hashtable names = new Hashtable();

		static SecNamedCurves()
		{
			objIds.Add("sect571r1", SecObjectIdentifiers.SecT571r1);
			objIds.Add("sect409r1", SecObjectIdentifiers.SecT409r1);       
			objIds.Add("sect283r1", SecObjectIdentifiers.SecT283r1);
			objIds.Add("sect233r1", SecObjectIdentifiers.SecT233r1);
			objIds.Add("sect163r2", SecObjectIdentifiers.SecT163r2);       
			objIds.Add("secp521r1", SecObjectIdentifiers.SecP521r1);       
			objIds.Add("secp256r1", SecObjectIdentifiers.SecP256r1);   
			objIds.Add("secp224r1", SecObjectIdentifiers.SecP224r1); 
			objIds.Add("secp384r1", SecObjectIdentifiers.SecP384r1); 

			names.Add(SecObjectIdentifiers.SecT571r1, "sect571r1");
			names.Add(SecObjectIdentifiers.SecT409r1, "sect409r1");       
			names.Add(SecObjectIdentifiers.SecT283r1, "sect283r1");
			names.Add(SecObjectIdentifiers.SecT233r1, "sect233r1");
			names.Add(SecObjectIdentifiers.SecT163r2, "sect163r2");       
			names.Add(SecObjectIdentifiers.SecP521r1, "secp521r1");       
			names.Add(SecObjectIdentifiers.SecP256r1, "secp256r1"); 
			names.Add(SecObjectIdentifiers.SecP224r1, "secp224r1");
			names.Add(SecObjectIdentifiers.SecP384r1, "secp384r1");

			curves.Add(SecObjectIdentifiers.SecT571r1, sect571r1);
			curves.Add(SecObjectIdentifiers.SecT409r1, sect409r1);       
			curves.Add(SecObjectIdentifiers.SecT283r1, sect283r1);
			curves.Add(SecObjectIdentifiers.SecT233r1, sect233r1);
			curves.Add(SecObjectIdentifiers.SecT163r2, sect163r2);       
			curves.Add(SecObjectIdentifiers.SecP521r1, secp521r1); 
			curves.Add(SecObjectIdentifiers.SecP256r1, secp256r1);
			curves.Add(SecObjectIdentifiers.SecP224r1, secp224r1);             
			curves.Add(SecObjectIdentifiers.SecP384r1, secp384r1);             
		}

		public static X9ECParameters GetByName(
			string name)
		{
			DerObjectIdentifier oid = (DerObjectIdentifier) objIds[name.ToLower(CultureInfo.InvariantCulture)];

			if (oid != null)
			{
				return (X9ECParameters) curves[oid];
			}

			return null;
		}

		/**
		 * return the X9ECParameters object for the named curve represented by
		 * the passed in object identifier. Null if the curve isn't present.
		 *
		 * @param oid an object identifier representing a named curve, if present.
		 */
		public static X9ECParameters GetByOid(
			DerObjectIdentifier oid)
		{
			return (X9ECParameters) curves[oid];
		}

		/**
		 * return the object identifier signified by the passed in name. Null
		 * if there is no object identifier associated with name.
		 *
		 * @return the object identifier associated with name, if present.
		 */
		public static DerObjectIdentifier GetOid(
			string name)
		{
			return (DerObjectIdentifier) objIds[name];
		}

		/**
		 * return the named curve name represented by the given object identifier.
		 */
		public static string GetName(
			DerObjectIdentifier oid)
		{
			return (string) names[oid];
		}

		/**
		 * returns an enumeration containing the name strings for curves
		 * contained in this structure.
		 */
		public static IEnumerable Names
		{
			get { return new EnumerableProxy(objIds.Keys); }
		}
	}
}
