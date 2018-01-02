using System;
using System.Text;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities.Encoders;

namespace AnLib.Util
{
    public sealed class AnLibRSA
    {
        /// <summary>
        /// RSAMD5签名
        /// </summary>
        /// <remarks>
        /// 2017.12.01: 创建. AnLib
        /// </remarks>
        /// <param name="privatekey">私钥</param>
        /// <param name="content">需要签名的数据</param>
        /// <returns>签名结果</returns>
        public static string RSASign(string privateKey, string content)
        {
            privateKey = AnLibRSA.RSAPrivateKeyJava2DotNet(privateKey);
            byte[] btContent = Encoding.UTF8.GetBytes(content);
            byte[] hv = MD5.Create().ComputeHash(btContent);
            RSACryptoServiceProvider rsp = new RSACryptoServiceProvider();
            rsp.FromXmlString(privateKey);
            RSAPKCS1SignatureFormatter rf = new RSAPKCS1SignatureFormatter(rsp);
            rf.SetHashAlgorithm("MD5");
            byte[] signature = rf.CreateSignature(hv);
            return Convert.ToBase64String(signature);
        }

        /// <summary>
        /// RSA私钥格式转换，java->.net
        /// </summary>
        /// <param name="privateKey">java生成的RSA私钥</param>
        /// <returns>.netRSA私钥</returns>
        public static string RSAPrivateKeyJava2DotNet(string privateKey)
        {
            RsaPrivateCrtKeyParameters privateKeyParam = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));

            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                Convert.ToBase64String(privateKeyParam.Modulus.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.PublicExponent.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.P.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.Q.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.DP.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.DQ.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.QInv.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.Exponent.ToByteArrayUnsigned()));
        }

        /// <summary>
        /// 利用工具类和JAVA生产的公钥加密字符串
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="content">加密前的字符串</param>
        /// <returns>加密后的字符串</returns>
        public static string RSAEncrypt(string publicKey, string content)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
            AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.CreateKey(publicKeyBytes);
            RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;
            RSAParameters rsaParameters = new RSAParameters();
            rsaParameters.Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned();
            rsaParameters.Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned();
            rsa.ImportParameters(rsaParameters);
            return Convert.ToBase64String(rsa.Encrypt(Encoding.GetEncoding("UTF-8").GetBytes(content), false));
        }

    }
}
