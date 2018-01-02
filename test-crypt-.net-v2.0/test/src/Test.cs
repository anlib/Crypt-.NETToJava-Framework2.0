using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using AnLib.Util;
namespace Test
{
    class Test
    {    
        /// <summary>
        /// 测试类集合
        /// </summary>      
        /// <remarks>
        /// 2017.12.01: 创建. AnLib <br/>
        /// </remarks>

        /// <summary>
        /// httpPost提交
        /// </summary>
        /// <returns></returns>
        public static String httpPost()
        {
            //提交网址设置
            String URL = "https://www.baidu.com";
            String userName = "libing";
            String postStr = "&userName=" + userName;
            //推送
            String returnMsg = HttpPost.PostData(URL, postStr);
            //返回结果
            return returnMsg;
        }
        //MD5加密
        public static String MD5()
        {
            String str = "AnLib测试";
            //MD5加密
            return AnLibMD5.MD5Encrypt(str);
        }
        //RSA签名
        public static String RSASign()
        {
            //签名参数
            String str = "AnLib测试";
            //构造java数据签名
            String sign = AnLibRSA.RSASign(Properties.Settings.Default.privateKey, str);
            //返回结果
            return sign;
        }
        //RSA加密
        public static String RSAEncrypt()
        {
            //参数
            String str = "AnLib测试";
            //构造java数据加密
            String encrypt = AnLibRSA.RSAEncrypt(Properties.Settings.Default.publicKey, str);
            //返回结果
            return encrypt;
        }
        //SM3加密
        public static String SM3()
        {
            //参数
            String str = "AnLib测试";
            //构造数据加密
            String encrypt = AnLibSM3.SM3Encrypt(str);
            //返回结果
            return encrypt;
        }
    }
}
