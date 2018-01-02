using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

namespace Test
{
    public partial class FormTest : Form
    {
        /// <summary>
        /// 窗体应用程序处理
        /// </summary>  
        /// <remarks>
        /// 2017.12.01: 创建. 李兵
        /// </remarks>
        public FormTest()
        {
            InitializeComponent();
        }
        /// <summary>
        /// 测试
        /// </summary>  
        
        /// <summary>
        /// 清楚返回打印信息
        /// </summary> 
        private void buttonClean_Click(object sender, EventArgs e)
        {
            webBrowserShow.DocumentText = "";
        }
        /// <summary>
        /// 测试 httpPost
        /// </summary>  
        private void httpPost_Click(object sender, EventArgs e)
        {
            webBrowserShow.DocumentText = Test.httpPost();
        }
        /// <summary>
        /// MD5加密
        /// </summary>  
        private void MD5_Click(object sender, EventArgs e)
        {
            webBrowserShow.DocumentText = Test.MD5();
        }
        /// <summary>
        /// RSA签名
        /// </summary>  
        private void RSASign_Click(object sender, EventArgs e)
        {
            webBrowserShow.DocumentText = Test.RSASign();
        }
        /// <summary>
        /// 国密3加密
        /// </summary>  
        private void sm3_Click(object sender, EventArgs e)
        {
            webBrowserShow.DocumentText = Test.SM3();
        }
        /// <summary>
        /// RSA加密
        /// </summary>  
        private void RSAEncrypt_Click(object sender, EventArgs e)
        {
            webBrowserShow.DocumentText = Test.RSAEncrypt();
        }
    }
}
