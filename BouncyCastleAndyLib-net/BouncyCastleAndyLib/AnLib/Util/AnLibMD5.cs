using System;
using System.Security.Cryptography;
using System.Text;

namespace AnLib.Util
{
    public sealed class AnLibMD5
    {
        ///   <summary>
        ///   给一个字符串进行MD5加密
        ///   </summary>
        ///   <param   name="input">待加密字符串</param>
        ///   <returns>加密后的字符串</returns>
        public static string MD5Encrypt2(string input)
        {
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] result = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(input));
            return System.Text.Encoding.Default.GetString(result);
        }
        public static string MD5Encrypt(string input)
        {

            byte[] result = Encoding.UTF8.GetBytes(input);
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] output = md5.ComputeHash(result);
            return BitConverter.ToString(output).Replace("-", ""); 
        }

        // Verify a hash against a string.
        public static bool verifyMd5(string input, string hash)
        {
            // Hash the input.
            string hashOfInput = MD5Encrypt(input);

            // Create a StringComparer an comare the hashes.
            StringComparer comparer = StringComparer.OrdinalIgnoreCase;

            if (0 == comparer.Compare(hashOfInput, hash))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

   
    }
}