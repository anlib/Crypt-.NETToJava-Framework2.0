using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Engines
{

    /**
    * an implementation of the AES (Rijndael), from FIPS-197.
    * <p>
    * For further details see: <a href="http://csrc.nist.gov/encryption/aes/">http://csrc.nist.gov/encryption/aes/</a>.
    *
    * This implementation is based on optimizations from Dr. Brian Gladman's paper and C code at
    * <a href="http://fp.gladman.plus.com/cryptography_technology/rijndael/">http://fp.gladman.plus.com/cryptography_technology/rijndael/</a>
    *
    * There are three levels of tradeoff of speed vs memory
    * Because java has no preprocessor, they are written as three separate classes from which to choose
    *
    * The fastest uses 8Kbytes of static tables to precompute round calculations, 4 256 word tables for encryption
    * and 4 for decryption.
    *
    * The middle performance version uses only one 256 word table for each, for a total of 2Kbytes,
    * adding 12 rotate operations per round to compute the values contained in the other tables from
    * the contents of the first.
    *
    * The slowest version uses no static tables at all and computes the values in each round.
    * <p>
    * This file contains the middle performance version with 2Kbytes of static tables for round precomputation.
    *
    */
    public class AesEngine
		: IBlockCipher
    {
        // The S box
        private static readonly byte[] S = {
            (byte)99, (byte)124, (byte)119, (byte)123, (byte)242, (byte)107, (byte)111, (byte)197,
            (byte)48,   (byte)1, (byte)103,  (byte)43, (byte)254, (byte)215, (byte)171, (byte)118,
            (byte)202, (byte)130, (byte)201, (byte)125, (byte)250,  (byte)89,  (byte)71, (byte)240,
            (byte)173, (byte)212, (byte)162, (byte)175, (byte)156, (byte)164, (byte)114, (byte)192,
            (byte)183, (byte)253, (byte)147,  (byte)38,  (byte)54,  (byte)63, (byte)247, (byte)204,
            (byte)52, (byte)165, (byte)229, (byte)241, (byte)113, (byte)216,  (byte)49,  (byte)21,
            (byte)4, (byte)199,  (byte)35, (byte)195,  (byte)24, (byte)150,   (byte)5, (byte)154,
            (byte)7,  (byte)18, (byte)128, (byte)226, (byte)235,  (byte)39, (byte)178, (byte)117,
            (byte)9, (byte)131,  (byte)44,  (byte)26,  (byte)27, (byte)110,  (byte)90, (byte)160,
            (byte)82,  (byte)59, (byte)214, (byte)179,  (byte)41, (byte)227,  (byte)47, (byte)132,
            (byte)83, (byte)209,   (byte)0, (byte)237,  (byte)32, (byte)252, (byte)177,  (byte)91,
            (byte)106, (byte)203, (byte)190,  (byte)57,  (byte)74,  (byte)76,  (byte)88, (byte)207,
            (byte)208, (byte)239, (byte)170, (byte)251,  (byte)67,  (byte)77,  (byte)51, (byte)133,
            (byte)69, (byte)249,   (byte)2, (byte)127,  (byte)80,  (byte)60, (byte)159, (byte)168,
            (byte)81, (byte)163,  (byte)64, (byte)143, (byte)146, (byte)157,  (byte)56, (byte)245,
            (byte)188, (byte)182, (byte)218,  (byte)33,  (byte)16, (byte)255, (byte)243, (byte)210,
            (byte)205,  (byte)12,  (byte)19, (byte)236,  (byte)95, (byte)151,  (byte)68,  (byte)23,
            (byte)196, (byte)167, (byte)126,  (byte)61, (byte)100,  (byte)93,  (byte)25, (byte)115,
            (byte)96, (byte)129,  (byte)79, (byte)220,  (byte)34,  (byte)42, (byte)144, (byte)136,
            (byte)70, (byte)238, (byte)184,  (byte)20, (byte)222,  (byte)94,  (byte)11, (byte)219,
            (byte)224,  (byte)50,  (byte)58,  (byte)10,  (byte)73,   (byte)6,  (byte)36,  (byte)92,
            (byte)194, (byte)211, (byte)172,  (byte)98, (byte)145, (byte)149, (byte)228, (byte)121,
            (byte)231, (byte)200,  (byte)55, (byte)109, (byte)141, (byte)213,  (byte)78, (byte)169,
            (byte)108,  (byte)86, (byte)244, (byte)234, (byte)101, (byte)122, (byte)174,   (byte)8,
            (byte)186, (byte)120,  (byte)37,  (byte)46,  (byte)28, (byte)166, (byte)180, (byte)198,
            (byte)232, (byte)221, (byte)116,  (byte)31,  (byte)75, (byte)189, (byte)139, (byte)138,
            (byte)112,  (byte)62, (byte)181, (byte)102,  (byte)72,   (byte)3, (byte)246,  (byte)14,
            (byte)97,  (byte)53,  (byte)87, (byte)185, (byte)134, (byte)193,  (byte)29, (byte)158,
            (byte)225, (byte)248, (byte)152,  (byte)17, (byte)105, (byte)217, (byte)142, (byte)148,
            (byte)155,  (byte)30, (byte)135, (byte)233, (byte)206,  (byte)85,  (byte)40, (byte)223,
            (byte)140, (byte)161, (byte)137,  (byte)13, (byte)191, (byte)230,  (byte)66, (byte)104,
            (byte)65, (byte)153,  (byte)45,  (byte)15, (byte)176,  (byte)84, (byte)187,  (byte)22,
        };

        // The inverse S-box
        private static readonly byte[] Si = {
            (byte)82,   (byte)9, (byte)106, (byte)213,  (byte)48,  (byte)54, (byte)165,  (byte)56,
            (byte)191,  (byte)64, (byte)163, (byte)158, (byte)129, (byte)243, (byte)215, (byte)251,
            (byte)124, (byte)227,  (byte)57, (byte)130, (byte)155,  (byte)47, (byte)255, (byte)135,
            (byte)52, (byte)142,  (byte)67,  (byte)68, (byte)196, (byte)222, (byte)233, (byte)203,
            (byte)84, (byte)123, (byte)148,  (byte)50, (byte)166, (byte)194,  (byte)35,  (byte)61,
            (byte)238,  (byte)76, (byte)149,  (byte)11,  (byte)66, (byte)250, (byte)195,  (byte)78,
            (byte)8,  (byte)46, (byte)161, (byte)102,  (byte)40, (byte)217,  (byte)36, (byte)178,
            (byte)118,  (byte)91, (byte)162,  (byte)73, (byte)109, (byte)139, (byte)209,  (byte)37,
            (byte)114, (byte)248, (byte)246, (byte)100, (byte)134, (byte)104, (byte)152,  (byte)22,
            (byte)212, (byte)164,  (byte)92, (byte)204,  (byte)93, (byte)101, (byte)182, (byte)146,
            (byte)108, (byte)112,  (byte)72,  (byte)80, (byte)253, (byte)237, (byte)185, (byte)218,
            (byte)94,  (byte)21,  (byte)70,  (byte)87, (byte)167, (byte)141, (byte)157, (byte)132,
            (byte)144, (byte)216, (byte)171,   (byte)0, (byte)140, (byte)188, (byte)211,  (byte)10,
            (byte)247, (byte)228,  (byte)88,   (byte)5, (byte)184, (byte)179,  (byte)69,   (byte)6,
            (byte)208,  (byte)44,  (byte)30, (byte)143, (byte)202,  (byte)63,  (byte)15,   (byte)2,
            (byte)193, (byte)175, (byte)189,   (byte)3,   (byte)1,  (byte)19, (byte)138, (byte)107,
            (byte)58, (byte)145,  (byte)17,  (byte)65,  (byte)79, (byte)103, (byte)220, (byte)234,
            (byte)151, (byte)242, (byte)207, (byte)206, (byte)240, (byte)180, (byte)230, (byte)115,
            (byte)150, (byte)172, (byte)116,  (byte)34, (byte)231, (byte)173,  (byte)53, (byte)133,
            (byte)226, (byte)249,  (byte)55, (byte)232,  (byte)28, (byte)117, (byte)223, (byte)110,
            (byte)71, (byte)241,  (byte)26, (byte)113,  (byte)29,  (byte)41, (byte)197, (byte)137,
            (byte)111, (byte)183,  (byte)98,  (byte)14, (byte)170,  (byte)24, (byte)190,  (byte)27,
            (byte)252,  (byte)86,  (byte)62,  (byte)75, (byte)198, (byte)210, (byte)121,  (byte)32,
            (byte)154, (byte)219, (byte)192, (byte)254, (byte)120, (byte)205,  (byte)90, (byte)244,
            (byte)31, (byte)221, (byte)168,  (byte)51, (byte)136,   (byte)7, (byte)199,  (byte)49,
            (byte)177,  (byte)18,  (byte)16,  (byte)89,  (byte)39, (byte)128, (byte)236,  (byte)95,
            (byte)96,  (byte)81, (byte)127, (byte)169,  (byte)25, (byte)181,  (byte)74,  (byte)13,
            (byte)45, (byte)229, (byte)122, (byte)159, (byte)147, (byte)201, (byte)156, (byte)239,
            (byte)160, (byte)224,  (byte)59,  (byte)77, (byte)174,  (byte)42, (byte)245, (byte)176,
            (byte)200, (byte)235, (byte)187,  (byte)60, (byte)131,  (byte)83, (byte)153,  (byte)97,
            (byte)23,  (byte)43,   (byte)4, (byte)126, (byte)186, (byte)119, (byte)214,  (byte)38,
            (byte)225, (byte)105,  (byte)20,  (byte)99,  (byte)85,  (byte)33,  (byte)12, (byte)125,
            };

        // vector used in calculating key schedule (powers of x in GF(256))
        private static readonly int[] rcon = {
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91 };

        // precomputation tables of calculations for rounds
        private static readonly int[] T0 =
        {
        unchecked((int) 0xa56363c6), unchecked((int) 0x847c7cf8), unchecked((int) 0x997777ee), unchecked((int) 0x8d7b7bf6), unchecked((int) 0x0df2f2ff),
        unchecked((int) 0xbd6b6bd6), unchecked((int) 0xb16f6fde), unchecked((int) 0x54c5c591), unchecked((int) 0x50303060), unchecked((int) 0x03010102),
        unchecked((int) 0xa96767ce), unchecked((int) 0x7d2b2b56), unchecked((int) 0x19fefee7), unchecked((int) 0x62d7d7b5), unchecked((int) 0xe6abab4d),
        unchecked((int) 0x9a7676ec), unchecked((int) 0x45caca8f), unchecked((int) 0x9d82821f), unchecked((int) 0x40c9c989), unchecked((int) 0x877d7dfa),
        unchecked((int) 0x15fafaef), unchecked((int) 0xeb5959b2), unchecked((int) 0xc947478e), unchecked((int) 0x0bf0f0fb), unchecked((int) 0xecadad41),
        unchecked((int) 0x67d4d4b3), unchecked((int) 0xfda2a25f), unchecked((int) 0xeaafaf45), unchecked((int) 0xbf9c9c23), unchecked((int) 0xf7a4a453),
        unchecked((int) 0x967272e4), unchecked((int) 0x5bc0c09b), unchecked((int) 0xc2b7b775), unchecked((int) 0x1cfdfde1), unchecked((int) 0xae93933d),
        unchecked((int) 0x6a26264c), unchecked((int) 0x5a36366c), unchecked((int) 0x413f3f7e), unchecked((int) 0x02f7f7f5), unchecked((int) 0x4fcccc83),
        unchecked((int) 0x5c343468), unchecked((int) 0xf4a5a551), unchecked((int) 0x34e5e5d1), unchecked((int) 0x08f1f1f9), unchecked((int) 0x937171e2),
        unchecked((int) 0x73d8d8ab), unchecked((int) 0x53313162), unchecked((int) 0x3f15152a), unchecked((int) 0x0c040408), unchecked((int) 0x52c7c795),
        unchecked((int) 0x65232346), unchecked((int) 0x5ec3c39d), unchecked((int) 0x28181830), unchecked((int) 0xa1969637), unchecked((int) 0x0f05050a),
        unchecked((int) 0xb59a9a2f), unchecked((int) 0x0907070e), unchecked((int) 0x36121224), unchecked((int) 0x9b80801b), unchecked((int) 0x3de2e2df),
        unchecked((int) 0x26ebebcd), unchecked((int) 0x6927274e), unchecked((int) 0xcdb2b27f), unchecked((int) 0x9f7575ea), unchecked((int) 0x1b090912),
        unchecked((int) 0x9e83831d), unchecked((int) 0x742c2c58), unchecked((int) 0x2e1a1a34), unchecked((int) 0x2d1b1b36), unchecked((int) 0xb26e6edc),
        unchecked((int) 0xee5a5ab4), unchecked((int) 0xfba0a05b), unchecked((int) 0xf65252a4), unchecked((int) 0x4d3b3b76), unchecked((int) 0x61d6d6b7),
        unchecked((int) 0xceb3b37d), unchecked((int) 0x7b292952), unchecked((int) 0x3ee3e3dd), unchecked((int) 0x712f2f5e), unchecked((int) 0x97848413),
        unchecked((int) 0xf55353a6), unchecked((int) 0x68d1d1b9), unchecked((int) 0x00000000), unchecked((int) 0x2cededc1), unchecked((int) 0x60202040),
        unchecked((int) 0x1ffcfce3), unchecked((int) 0xc8b1b179), unchecked((int) 0xed5b5bb6), unchecked((int) 0xbe6a6ad4), unchecked((int) 0x46cbcb8d),
        unchecked((int) 0xd9bebe67), unchecked((int) 0x4b393972), unchecked((int) 0xde4a4a94), unchecked((int) 0xd44c4c98), unchecked((int) 0xe85858b0),
        unchecked((int) 0x4acfcf85), unchecked((int) 0x6bd0d0bb), unchecked((int) 0x2aefefc5), unchecked((int) 0xe5aaaa4f), unchecked((int) 0x16fbfbed),
        unchecked((int) 0xc5434386), unchecked((int) 0xd74d4d9a), unchecked((int) 0x55333366), unchecked((int) 0x94858511), unchecked((int) 0xcf45458a),
        unchecked((int) 0x10f9f9e9), unchecked((int) 0x06020204), unchecked((int) 0x817f7ffe), unchecked((int) 0xf05050a0), unchecked((int) 0x443c3c78),
        unchecked((int) 0xba9f9f25), unchecked((int) 0xe3a8a84b), unchecked((int) 0xf35151a2), unchecked((int) 0xfea3a35d), unchecked((int) 0xc0404080),
        unchecked((int) 0x8a8f8f05), unchecked((int) 0xad92923f), unchecked((int) 0xbc9d9d21), unchecked((int) 0x48383870), unchecked((int) 0x04f5f5f1),
        unchecked((int) 0xdfbcbc63), unchecked((int) 0xc1b6b677), unchecked((int) 0x75dadaaf), unchecked((int) 0x63212142), unchecked((int) 0x30101020),
        unchecked((int) 0x1affffe5), unchecked((int) 0x0ef3f3fd), unchecked((int) 0x6dd2d2bf), unchecked((int) 0x4ccdcd81), unchecked((int) 0x140c0c18),
        unchecked((int) 0x35131326), unchecked((int) 0x2fececc3), unchecked((int) 0xe15f5fbe), unchecked((int) 0xa2979735), unchecked((int) 0xcc444488),
        unchecked((int) 0x3917172e), unchecked((int) 0x57c4c493), unchecked((int) 0xf2a7a755), unchecked((int) 0x827e7efc), unchecked((int) 0x473d3d7a),
        unchecked((int) 0xac6464c8), unchecked((int) 0xe75d5dba), unchecked((int) 0x2b191932), unchecked((int) 0x957373e6), unchecked((int) 0xa06060c0),
        unchecked((int) 0x98818119), unchecked((int) 0xd14f4f9e), unchecked((int) 0x7fdcdca3), unchecked((int) 0x66222244), unchecked((int) 0x7e2a2a54),
        unchecked((int) 0xab90903b), unchecked((int) 0x8388880b), unchecked((int) 0xca46468c), unchecked((int) 0x29eeeec7), unchecked((int) 0xd3b8b86b),
        unchecked((int) 0x3c141428), unchecked((int) 0x79dedea7), unchecked((int) 0xe25e5ebc), unchecked((int) 0x1d0b0b16), unchecked((int) 0x76dbdbad),
        unchecked((int) 0x3be0e0db), unchecked((int) 0x56323264), unchecked((int) 0x4e3a3a74), unchecked((int) 0x1e0a0a14), unchecked((int) 0xdb494992),
        unchecked((int) 0x0a06060c), unchecked((int) 0x6c242448), unchecked((int) 0xe45c5cb8), unchecked((int) 0x5dc2c29f), unchecked((int) 0x6ed3d3bd),
        unchecked((int) 0xefacac43), unchecked((int) 0xa66262c4), unchecked((int) 0xa8919139), unchecked((int) 0xa4959531), unchecked((int) 0x37e4e4d3),
        unchecked((int) 0x8b7979f2), unchecked((int) 0x32e7e7d5), unchecked((int) 0x43c8c88b), unchecked((int) 0x5937376e), unchecked((int) 0xb76d6dda),
        unchecked((int) 0x8c8d8d01), unchecked((int) 0x64d5d5b1), unchecked((int) 0xd24e4e9c), unchecked((int) 0xe0a9a949), unchecked((int) 0xb46c6cd8),
        unchecked((int) 0xfa5656ac), unchecked((int) 0x07f4f4f3), unchecked((int) 0x25eaeacf), unchecked((int) 0xaf6565ca), unchecked((int) 0x8e7a7af4),
        unchecked((int) 0xe9aeae47), unchecked((int) 0x18080810), unchecked((int) 0xd5baba6f), unchecked((int) 0x887878f0), unchecked((int) 0x6f25254a),
        unchecked((int) 0x722e2e5c), unchecked((int) 0x241c1c38), unchecked((int) 0xf1a6a657), unchecked((int) 0xc7b4b473), unchecked((int) 0x51c6c697),
        unchecked((int) 0x23e8e8cb), unchecked((int) 0x7cdddda1), unchecked((int) 0x9c7474e8), unchecked((int) 0x211f1f3e), unchecked((int) 0xdd4b4b96),
        unchecked((int) 0xdcbdbd61), unchecked((int) 0x868b8b0d), unchecked((int) 0x858a8a0f), unchecked((int) 0x907070e0), unchecked((int) 0x423e3e7c),
        unchecked((int) 0xc4b5b571), unchecked((int) 0xaa6666cc), unchecked((int) 0xd8484890), unchecked((int) 0x05030306), unchecked((int) 0x01f6f6f7),
        unchecked((int) 0x120e0e1c), unchecked((int) 0xa36161c2), unchecked((int) 0x5f35356a), unchecked((int) 0xf95757ae), unchecked((int) 0xd0b9b969),
        unchecked((int) 0x91868617), unchecked((int) 0x58c1c199), unchecked((int) 0x271d1d3a), unchecked((int) 0xb99e9e27), unchecked((int) 0x38e1e1d9),
        unchecked((int) 0x13f8f8eb), unchecked((int) 0xb398982b), unchecked((int) 0x33111122), unchecked((int) 0xbb6969d2), unchecked((int) 0x70d9d9a9),
        unchecked((int) 0x898e8e07), unchecked((int) 0xa7949433), unchecked((int) 0xb69b9b2d), unchecked((int) 0x221e1e3c), unchecked((int) 0x92878715),
        unchecked((int) 0x20e9e9c9), unchecked((int) 0x49cece87), unchecked((int) 0xff5555aa), unchecked((int) 0x78282850), unchecked((int) 0x7adfdfa5),
        unchecked((int) 0x8f8c8c03), unchecked((int) 0xf8a1a159), unchecked((int) 0x80898909), unchecked((int) 0x170d0d1a), unchecked((int) 0xdabfbf65),
        unchecked((int) 0x31e6e6d7), unchecked((int) 0xc6424284), unchecked((int) 0xb86868d0), unchecked((int) 0xc3414182), unchecked((int) 0xb0999929),
        unchecked((int) 0x772d2d5a), unchecked((int) 0x110f0f1e), unchecked((int) 0xcbb0b07b), unchecked((int) 0xfc5454a8), unchecked((int) 0xd6bbbb6d),
        unchecked((int) 0x3a16162c)};

    private static readonly int[] Tinv0 =
        {
        unchecked((int) 0x50a7f451), unchecked((int) 0x5365417e), unchecked((int) 0xc3a4171a), unchecked((int) 0x965e273a), unchecked((int) 0xcb6bab3b),
        unchecked((int) 0xf1459d1f), unchecked((int) 0xab58faac), unchecked((int) 0x9303e34b), unchecked((int) 0x55fa3020), unchecked((int) 0xf66d76ad),
        unchecked((int) 0x9176cc88), unchecked((int) 0x254c02f5), unchecked((int) 0xfcd7e54f), unchecked((int) 0xd7cb2ac5), unchecked((int) 0x80443526),
        unchecked((int) 0x8fa362b5), unchecked((int) 0x495ab1de), unchecked((int) 0x671bba25), unchecked((int) 0x980eea45), unchecked((int) 0xe1c0fe5d),
        unchecked((int) 0x02752fc3), unchecked((int) 0x12f04c81), unchecked((int) 0xa397468d), unchecked((int) 0xc6f9d36b), unchecked((int) 0xe75f8f03),
        unchecked((int) 0x959c9215), unchecked((int) 0xeb7a6dbf), unchecked((int) 0xda595295), unchecked((int) 0x2d83bed4), unchecked((int) 0xd3217458),
        unchecked((int) 0x2969e049), unchecked((int) 0x44c8c98e), unchecked((int) 0x6a89c275), unchecked((int) 0x78798ef4), unchecked((int) 0x6b3e5899),
        unchecked((int) 0xdd71b927), unchecked((int) 0xb64fe1be), unchecked((int) 0x17ad88f0), unchecked((int) 0x66ac20c9), unchecked((int) 0xb43ace7d),
        unchecked((int) 0x184adf63), unchecked((int) 0x82311ae5), unchecked((int) 0x60335197), unchecked((int) 0x457f5362), unchecked((int) 0xe07764b1),
        unchecked((int) 0x84ae6bbb), unchecked((int) 0x1ca081fe), unchecked((int) 0x942b08f9), unchecked((int) 0x58684870), unchecked((int) 0x19fd458f),
        unchecked((int) 0x876cde94), unchecked((int) 0xb7f87b52), unchecked((int) 0x23d373ab), unchecked((int) 0xe2024b72), unchecked((int) 0x578f1fe3),
        unchecked((int) 0x2aab5566), unchecked((int) 0x0728ebb2), unchecked((int) 0x03c2b52f), unchecked((int) 0x9a7bc586), unchecked((int) 0xa50837d3),
        unchecked((int) 0xf2872830), unchecked((int) 0xb2a5bf23), unchecked((int) 0xba6a0302), unchecked((int) 0x5c8216ed), unchecked((int) 0x2b1ccf8a),
        unchecked((int) 0x92b479a7), unchecked((int) 0xf0f207f3), unchecked((int) 0xa1e2694e), unchecked((int) 0xcdf4da65), unchecked((int) 0xd5be0506),
        unchecked((int) 0x1f6234d1), unchecked((int) 0x8afea6c4), unchecked((int) 0x9d532e34), unchecked((int) 0xa055f3a2), unchecked((int) 0x32e18a05),
        unchecked((int) 0x75ebf6a4), unchecked((int) 0x39ec830b), unchecked((int) 0xaaef6040), unchecked((int) 0x069f715e), unchecked((int) 0x51106ebd),
        unchecked((int) 0xf98a213e), unchecked((int) 0x3d06dd96), unchecked((int) 0xae053edd), unchecked((int) 0x46bde64d), unchecked((int) 0xb58d5491),
        unchecked((int) 0x055dc471), unchecked((int) 0x6fd40604), unchecked((int) 0xff155060), unchecked((int) 0x24fb9819), unchecked((int) 0x97e9bdd6),
        unchecked((int) 0xcc434089), unchecked((int) 0x779ed967), unchecked((int) 0xbd42e8b0), unchecked((int) 0x888b8907), unchecked((int) 0x385b19e7),
        unchecked((int) 0xdbeec879), unchecked((int) 0x470a7ca1), unchecked((int) 0xe90f427c), unchecked((int) 0xc91e84f8), unchecked((int) 0x00000000),
        unchecked((int) 0x83868009), unchecked((int) 0x48ed2b32), unchecked((int) 0xac70111e), unchecked((int) 0x4e725a6c), unchecked((int) 0xfbff0efd),
        unchecked((int) 0x5638850f), unchecked((int) 0x1ed5ae3d), unchecked((int) 0x27392d36), unchecked((int) 0x64d90f0a), unchecked((int) 0x21a65c68),
        unchecked((int) 0xd1545b9b), unchecked((int) 0x3a2e3624), unchecked((int) 0xb1670a0c), unchecked((int) 0x0fe75793), unchecked((int) 0xd296eeb4),
        unchecked((int) 0x9e919b1b), unchecked((int) 0x4fc5c080), unchecked((int) 0xa220dc61), unchecked((int) 0x694b775a), unchecked((int) 0x161a121c),
        unchecked((int) 0x0aba93e2), unchecked((int) 0xe52aa0c0), unchecked((int) 0x43e0223c), unchecked((int) 0x1d171b12), unchecked((int) 0x0b0d090e),
        unchecked((int) 0xadc78bf2), unchecked((int) 0xb9a8b62d), unchecked((int) 0xc8a91e14), unchecked((int) 0x8519f157), unchecked((int) 0x4c0775af),
        unchecked((int) 0xbbdd99ee), unchecked((int) 0xfd607fa3), unchecked((int) 0x9f2601f7), unchecked((int) 0xbcf5725c), unchecked((int) 0xc53b6644),
        unchecked((int) 0x347efb5b), unchecked((int) 0x7629438b), unchecked((int) 0xdcc623cb), unchecked((int) 0x68fcedb6), unchecked((int) 0x63f1e4b8),
        unchecked((int) 0xcadc31d7), unchecked((int) 0x10856342), unchecked((int) 0x40229713), unchecked((int) 0x2011c684), unchecked((int) 0x7d244a85),
        unchecked((int) 0xf83dbbd2), unchecked((int) 0x1132f9ae), unchecked((int) 0x6da129c7), unchecked((int) 0x4b2f9e1d), unchecked((int) 0xf330b2dc),
        unchecked((int) 0xec52860d), unchecked((int) 0xd0e3c177), unchecked((int) 0x6c16b32b), unchecked((int) 0x99b970a9), unchecked((int) 0xfa489411),
        unchecked((int) 0x2264e947), unchecked((int) 0xc48cfca8), unchecked((int) 0x1a3ff0a0), unchecked((int) 0xd82c7d56), unchecked((int) 0xef903322),
        unchecked((int) 0xc74e4987), unchecked((int) 0xc1d138d9), unchecked((int) 0xfea2ca8c), unchecked((int) 0x360bd498), unchecked((int) 0xcf81f5a6),
        unchecked((int) 0x28de7aa5), unchecked((int) 0x268eb7da), unchecked((int) 0xa4bfad3f), unchecked((int) 0xe49d3a2c), unchecked((int) 0x0d927850),
        unchecked((int) 0x9bcc5f6a), unchecked((int) 0x62467e54), unchecked((int) 0xc2138df6), unchecked((int) 0xe8b8d890), unchecked((int) 0x5ef7392e),
        unchecked((int) 0xf5afc382), unchecked((int) 0xbe805d9f), unchecked((int) 0x7c93d069), unchecked((int) 0xa92dd56f), unchecked((int) 0xb31225cf),
        unchecked((int) 0x3b99acc8), unchecked((int) 0xa77d1810), unchecked((int) 0x6e639ce8), unchecked((int) 0x7bbb3bdb), unchecked((int) 0x097826cd),
        unchecked((int) 0xf418596e), unchecked((int) 0x01b79aec), unchecked((int) 0xa89a4f83), unchecked((int) 0x656e95e6), unchecked((int) 0x7ee6ffaa),
        unchecked((int) 0x08cfbc21), unchecked((int) 0xe6e815ef), unchecked((int) 0xd99be7ba), unchecked((int) 0xce366f4a), unchecked((int) 0xd4099fea),
        unchecked((int) 0xd67cb029), unchecked((int) 0xafb2a431), unchecked((int) 0x31233f2a), unchecked((int) 0x3094a5c6), unchecked((int) 0xc066a235),
        unchecked((int) 0x37bc4e74), unchecked((int) 0xa6ca82fc), unchecked((int) 0xb0d090e0), unchecked((int) 0x15d8a733), unchecked((int) 0x4a9804f1),
        unchecked((int) 0xf7daec41), unchecked((int) 0x0e50cd7f), unchecked((int) 0x2ff69117), unchecked((int) 0x8dd64d76), unchecked((int) 0x4db0ef43),
        unchecked((int) 0x544daacc), unchecked((int) 0xdf0496e4), unchecked((int) 0xe3b5d19e), unchecked((int) 0x1b886a4c), unchecked((int) 0xb81f2cc1),
        unchecked((int) 0x7f516546), unchecked((int) 0x04ea5e9d), unchecked((int) 0x5d358c01), unchecked((int) 0x737487fa), unchecked((int) 0x2e410bfb),
        unchecked((int) 0x5a1d67b3), unchecked((int) 0x52d2db92), unchecked((int) 0x335610e9), unchecked((int) 0x1347d66d), unchecked((int) 0x8c61d79a),
        unchecked((int) 0x7a0ca137), unchecked((int) 0x8e14f859), unchecked((int) 0x893c13eb), unchecked((int) 0xee27a9ce), unchecked((int) 0x35c961b7),
        unchecked((int) 0xede51ce1), unchecked((int) 0x3cb1477a), unchecked((int) 0x59dfd29c), unchecked((int) 0x3f73f255), unchecked((int) 0x79ce1418),
        unchecked((int) 0xbf37c773), unchecked((int) 0xeacdf753), unchecked((int) 0x5baafd5f), unchecked((int) 0x146f3ddf), unchecked((int) 0x86db4478),
        unchecked((int) 0x81f3afca), unchecked((int) 0x3ec468b9), unchecked((int) 0x2c342438), unchecked((int) 0x5f40a3c2), unchecked((int) 0x72c31d16),
        unchecked((int) 0x0c25e2bc), unchecked((int) 0x8b493c28), unchecked((int) 0x41950dff), unchecked((int) 0x7101a839), unchecked((int) 0xdeb30c08),
        unchecked((int) 0x9ce4b4d8), unchecked((int) 0x90c15664), unchecked((int) 0x6184cb7b), unchecked((int) 0x70b632d5), unchecked((int) 0x745c6c48),
        unchecked((int) 0x4257b8d0)};

		private int Shift(
            int	r,
            int	shift)
        {
            return ((int)(((uint) r >> shift) | (uint)(r << (32 - shift))));
        }


		/* multiply four bytes in GF(2^8) by 'x' {02} in parallel */

        private const int m1 = unchecked((int) 0x80808080);
        private const int m2 = unchecked((int) 0x7f7f7f7f);
        private const int m3 = unchecked((int) 0x0000001b);

		private int FFmulX(
			int x)
        {
            return ((int) (((x & m2) << 1) ^ (( (uint) (x & m1) >> 7) * m3)));
        }


		/*
        The following defines provide alternative definitions of FFmulX that might
        give improved performance if a fast 32-bit multiply is not available.

        private int FFmulX(int x) { int u = x & m1; u |= (u >> 1); return ((x & m2) << 1) ^ ((u >>> 3) | (u >>> 6)); }
        private static final int  m4 = 0x1b1b1b1b;
        private int FFmulX(int x) { int u = x & m1; return ((x & m2) << 1) ^ ((u - (u >>> 7)) & m4); }

        */

		private int Inv_Mcol(
			int x)
		{
            int f2 = FFmulX(x);
            int f4 = FFmulX(f2);
            int f8 = FFmulX(f4);
            int f9 = x ^ f8;

            return f2 ^ f4 ^ f8 ^ Shift(f2 ^ f9, 8) ^ Shift(f4 ^ f9, 16) ^ Shift(f9, 24);
        }

        private int SubWord(int x) {
            return (S[x&255]&255 | ((S[(x>>8)&255]&255)<<8) | ((S[(x>>16)&255]&255)<<16) | S[(x>>24)&255]<<24);
        }

        /**
        * Calculate the necessary round keys
        * The number of calculations depends on key size and block size
        * AES specified a fixed block size of 128 bits and key sizes 128/192/256 bits
        * This code is written assuming those are the only possible values
        */
        private int[,] GenerateWorkingKey(
            byte[]	key,
            bool	forEncryption)
        {
            int KC = key.Length / 4;  // key length in words
            int t;

			if ((KC != 4) && (KC != 6) && (KC != 8)) {
                throw new ArgumentException("Key length not 128/192/256 bits.");
            }

			ROUNDS = KC + 6;  // This is not always true for the generalized Rijndael that allows larger block sizes
            int[,] W = new int[ROUNDS+1, 4];   // 4 words in a block

			//
            // copy the key into the round key array
            //

			t = 0;
            for (int i = 0; i < key.Length; t++)
            {
                W[t >> 2, t & 3] = (key[i]&0xff) | ((key[i+1]&0xff) << 8) | ((key[i+2]&0xff) << 16) | (key[i+3] << 24);
                i+=4;
            }

			//
            // while not enough round key material calculated
            // calculate new values
            //
            int k = (ROUNDS + 1) << 2;
            for (int i = KC; (i < k); i++)
            {
                int temp = W[(i-1)>>2, (i-1)&3];
                if ((i % KC) == 0) {
                    temp = SubWord(Shift(temp, 8)) ^ rcon[(i / KC)-1];
                } else if ((KC > 6) && ((i % KC) == 4)) {
                    temp = SubWord(temp);
                }

                W[i>>2, i&3] = W[(i - KC)>>2, (i-KC)&3] ^ temp;
            }

			if (!forEncryption)
			{
                for (int j = 1; j < ROUNDS; j++)
				{
                    for (int i = 0; i < 4; i++)
					{
						W[j, i] = Inv_Mcol(W[j, i]);
                    }
                }
            }

			return W;
        }

		private int ROUNDS;
        private int[,] WorkingKey;
        private int C0, C1, C2, C3;
        private bool forEncryption;

		private const int BLOCK_SIZE = 16;

		/**
        * default constructor - 128 bit block size.
        */
        public AesEngine()
        {
        }

		/**
        * initialise an AES cipher.
        *
        * @param forEncryption whether or not we are for encryption.
        * @param parameters the parameters required to set up the cipher.
        * @exception ArgumentException if the parameters argument is
        * inappropriate.
        */
        public void Init(
            bool				forEncryption,
            ICipherParameters	parameters)
        {
			KeyParameter keyParameter = parameters as KeyParameter;

			if (keyParameter == null)
				throw new ArgumentException("invalid parameter passed to AES init - " + parameters.GetType().Name);

			WorkingKey = GenerateWorkingKey(keyParameter.GetKey(), forEncryption);

			this.forEncryption = forEncryption;
        }

		public string AlgorithmName
        {
            get { return "AES"; }
        }

		public bool IsPartialBlockOkay
		{
			get { return false; }
		}

		public int GetBlockSize()
        {
            return BLOCK_SIZE;
        }

		public int ProcessBlock(
            byte[]	input,
            int		inOff,
            byte[]	output,
            int		outOff)
        {
            if (WorkingKey == null)
            {
                throw new InvalidOperationException("AES engine not initialised");
            }

			if ((inOff + (32 / 2)) > input.Length)
            {
                throw new DataLengthException("input buffer too short");
            }

			if ((outOff + (32 / 2)) > output.Length)
            {
                throw new DataLengthException("output buffer too short");
            }

			UnPackBlock(input, inOff);

			if (forEncryption)
            {
                EncryptBlock(WorkingKey);
            }
            else
            {
                DecryptBlock(WorkingKey);
            }

			PackBlock(output, outOff);

			return BLOCK_SIZE;
        }

        public void Reset()
        {
        }

		private void UnPackBlock(
            byte[]	bytes,
            int		off)
        {
            int index = off;

			C0 = (bytes[index++] & 0xff);
            C0 |= (bytes[index++] & 0xff) << 8;
            C0 |= (bytes[index++] & 0xff) << 16;
            C0 |= bytes[index++] << 24;

            C1 = (bytes[index++] & 0xff);
            C1 |= (bytes[index++] & 0xff) << 8;
            C1 |= (bytes[index++] & 0xff) << 16;
            C1 |= bytes[index++] << 24;

            C2 = (bytes[index++] & 0xff);
            C2 |= (bytes[index++] & 0xff) << 8;
            C2 |= (bytes[index++] & 0xff) << 16;
            C2 |= bytes[index++] << 24;

            C3 = (bytes[index++] & 0xff);
            C3 |= (bytes[index++] & 0xff) << 8;
            C3 |= (bytes[index++] & 0xff) << 16;
            C3 |= bytes[index++] << 24;
        }

		private void PackBlock(
            byte[]	bytes,
            int		off)
        {
            int index = off;

			bytes[index++] = (byte)C0;
            bytes[index++] = (byte)(C0 >> 8);
            bytes[index++] = (byte)(C0 >> 16);
            bytes[index++] = (byte)(C0 >> 24);

			bytes[index++] = (byte)C1;
            bytes[index++] = (byte)(C1 >> 8);
            bytes[index++] = (byte)(C1 >> 16);
            bytes[index++] = (byte)(C1 >> 24);

			bytes[index++] = (byte)C2;
            bytes[index++] = (byte)(C2 >> 8);
            bytes[index++] = (byte)(C2 >> 16);
            bytes[index++] = (byte)(C2 >> 24);

			bytes[index++] = (byte)C3;
            bytes[index++] = (byte)(C3 >> 8);
            bytes[index++] = (byte)(C3 >> 16);
            bytes[index++] = (byte)(C3 >> 24);
        }

		private void EncryptBlock(
			int[,] KW)
        {
            int r, r0, r1, r2, r3;

			C0 ^= KW[0, 0];
            C1 ^= KW[0, 1];
            C2 ^= KW[0, 2];
            C3 ^= KW[0, 3];

            for (r = 1; r < ROUNDS - 1;)
			{
                r0 = T0[C0&255] ^ Shift(T0[(C1>>8)&255], 24) ^ Shift(T0[(C2>>16)&255],16) ^ Shift(T0[(C3>>24)&255],8) ^ KW[r,0];
                r1 = T0[C1&255] ^ Shift(T0[(C2>>8)&255], 24) ^ Shift(T0[(C3>>16)&255], 16) ^ Shift(T0[(C0>>24)&255], 8) ^ KW[r,1];
                r2 = T0[C2&255] ^ Shift(T0[(C3>>8)&255], 24) ^ Shift(T0[(C0>>16)&255], 16) ^ Shift(T0[(C1>>24)&255], 8) ^ KW[r,2];
                r3 = T0[C3&255] ^ Shift(T0[(C0>>8)&255], 24) ^ Shift(T0[(C1>>16)&255], 16) ^ Shift(T0[(C2>>24)&255], 8) ^ KW[r++,3];
                C0 = T0[r0&255] ^ Shift(T0[(r1>>8)&255], 24) ^ Shift(T0[(r2>>16)&255], 16) ^ Shift(T0[(r3>>24)&255], 8) ^ KW[r,0];
                C1 = T0[r1&255] ^ Shift(T0[(r2>>8)&255], 24) ^ Shift(T0[(r3>>16)&255], 16) ^ Shift(T0[(r0>>24)&255], 8) ^ KW[r,1];
                C2 = T0[r2&255] ^ Shift(T0[(r3>>8)&255], 24) ^ Shift(T0[(r0>>16)&255], 16) ^ Shift(T0[(r1>>24)&255], 8) ^ KW[r,2];
                C3 = T0[r3&255] ^ Shift(T0[(r0>>8)&255], 24) ^ Shift(T0[(r1>>16)&255], 16) ^ Shift(T0[(r2>>24)&255], 8) ^ KW[r++,3];
            }

            r0 = T0[C0&255] ^ Shift(T0[(C1>>8)&255], 24) ^ Shift(T0[(C2>>16)&255], 16) ^ Shift(T0[(C3>>24)&255], 8) ^ KW[r,0];
            r1 = T0[C1&255] ^ Shift(T0[(C2>>8)&255], 24) ^ Shift(T0[(C3>>16)&255], 16) ^ Shift(T0[(C0>>24)&255], 8) ^ KW[r,1];
            r2 = T0[C2&255] ^ Shift(T0[(C3>>8)&255], 24) ^ Shift(T0[(C0>>16)&255], 16) ^ Shift(T0[(C1>>24)&255], 8) ^ KW[r,2];
            r3 = T0[C3&255] ^ Shift(T0[(C0>>8)&255], 24) ^ Shift(T0[(C1>>16)&255], 16) ^ Shift(T0[(C2>>24)&255], 8) ^ KW[r++,3];

            // the final round's table is a simple function of S so we don't use a whole other four tables for it

            C0 = (S[r0&255]&255) ^ ((S[(r1>>8)&255]&255)<<8) ^ ((S[(r2>>16)&255]&255)<<16) ^ (S[(r3>>24)&255]<<24) ^ KW[r,0];
            C1 = (S[r1&255]&255) ^ ((S[(r2>>8)&255]&255)<<8) ^ ((S[(r3>>16)&255]&255)<<16) ^ (S[(r0>>24)&255]<<24) ^ KW[r,1];
            C2 = (S[r2&255]&255) ^ ((S[(r3>>8)&255]&255)<<8) ^ ((S[(r0>>16)&255]&255)<<16) ^ (S[(r1>>24)&255]<<24) ^ KW[r,2];
            C3 = (S[r3&255]&255) ^ ((S[(r0>>8)&255]&255)<<8) ^ ((S[(r1>>16)&255]&255)<<16) ^ (S[(r2>>24)&255]<<24) ^ KW[r,3];
        }

		private void DecryptBlock(
			int[,] KW)
        {
            int r, r0, r1, r2, r3;

			C0 ^= KW[ROUNDS,0];
            C1 ^= KW[ROUNDS,1];
            C2 ^= KW[ROUNDS,2];
            C3 ^= KW[ROUNDS,3];

			for (r = ROUNDS-1; r>1;)
			{
                r0 = Tinv0[C0&255] ^ Shift(Tinv0[(C3>>8)&255], 24) ^ Shift(Tinv0[(C2>>16)&255], 16) ^ Shift(Tinv0[(C1>>24)&255], 8) ^ KW[r,0];
                r1 = Tinv0[C1&255] ^ Shift(Tinv0[(C0>>8)&255], 24) ^ Shift(Tinv0[(C3>>16)&255], 16) ^ Shift(Tinv0[(C2>>24)&255], 8) ^ KW[r,1];
                r2 = Tinv0[C2&255] ^ Shift(Tinv0[(C1>>8)&255], 24) ^ Shift(Tinv0[(C0>>16)&255], 16) ^ Shift(Tinv0[(C3>>24)&255], 8) ^ KW[r,2];
                r3 = Tinv0[C3&255] ^ Shift(Tinv0[(C2>>8)&255], 24) ^ Shift(Tinv0[(C1>>16)&255], 16) ^ Shift(Tinv0[(C0>>24)&255], 8) ^ KW[r--,3];
                C0 = Tinv0[r0&255] ^ Shift(Tinv0[(r3>>8)&255], 24) ^ Shift(Tinv0[(r2>>16)&255], 16) ^ Shift(Tinv0[(r1>>24)&255], 8) ^ KW[r,0];
                C1 = Tinv0[r1&255] ^ Shift(Tinv0[(r0>>8)&255], 24) ^ Shift(Tinv0[(r3>>16)&255], 16) ^ Shift(Tinv0[(r2>>24)&255], 8) ^ KW[r,1];
                C2 = Tinv0[r2&255] ^ Shift(Tinv0[(r1>>8)&255], 24) ^ Shift(Tinv0[(r0>>16)&255], 16) ^ Shift(Tinv0[(r3>>24)&255], 8) ^ KW[r,2];
                C3 = Tinv0[r3&255] ^ Shift(Tinv0[(r2>>8)&255], 24) ^ Shift(Tinv0[(r1>>16)&255], 16) ^ Shift(Tinv0[(r0>>24)&255], 8) ^ KW[r--,3];
            }

            r0 = Tinv0[C0&255] ^ Shift(Tinv0[(C3>>8)&255], 24) ^ Shift(Tinv0[(C2>>16)&255], 16) ^ Shift(Tinv0[(C1>>24)&255], 8) ^ KW[r,0];
            r1 = Tinv0[C1&255] ^ Shift(Tinv0[(C0>>8)&255], 24) ^ Shift(Tinv0[(C3>>16)&255], 16) ^ Shift(Tinv0[(C2>>24)&255], 8) ^ KW[r,1];
            r2 = Tinv0[C2&255] ^ Shift(Tinv0[(C1>>8)&255], 24) ^ Shift(Tinv0[(C0>>16)&255], 16) ^ Shift(Tinv0[(C3>>24)&255], 8) ^ KW[r,2];
            r3 = Tinv0[C3&255] ^ Shift(Tinv0[(C2>>8)&255], 24) ^ Shift(Tinv0[(C1>>16)&255], 16) ^ Shift(Tinv0[(C0>>24)&255], 8) ^ KW[r,3];

			// the final round's table is a simple function of Si so we don't use a whole other four tables for it

			C0 = (Si[r0&255]&255) ^ ((Si[(r3>>8)&255]&255)<<8) ^ ((Si[(r2>>16)&255]&255)<<16) ^ (Si[(r1>>24)&255]<<24) ^ KW[0,0];
            C1 = (Si[r1&255]&255) ^ ((Si[(r0>>8)&255]&255)<<8) ^ ((Si[(r3>>16)&255]&255)<<16) ^ (Si[(r2>>24)&255]<<24) ^ KW[0,1];
            C2 = (Si[r2&255]&255) ^ ((Si[(r1>>8)&255]&255)<<8) ^ ((Si[(r0>>16)&255]&255)<<16) ^ (Si[(r3>>24)&255]<<24) ^ KW[0,2];
            C3 = (Si[r3&255]&255) ^ ((Si[(r2>>8)&255]&255)<<8) ^ ((Si[(r1>>16)&255]&255)<<16) ^ (Si[(r0>>24)&255]<<24) ^ KW[0,3];
        }
    }
}
