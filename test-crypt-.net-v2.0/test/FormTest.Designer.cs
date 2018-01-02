namespace Test
{
    partial class FormTest
    {
        /// <summary>
        /// 必需的设计器变量
        /// </summary>      
        /// <remarks>
        /// 2017.12.01: 创建. 李兵 <br/>
        /// </remarks>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// 清理所有正在使用的资源
        /// </summary>
        /// <param name="disposing">如果应释放托管资源，为 true；否则为 false。</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows 窗体设计器生成的代码

        /// <summary>
        /// 设计器支持所需的方法 - 不要
        /// 使用代码编辑器修改此方法的内容。
        /// </summary>
        private void InitializeComponent()
        {
            this.httpPost = new System.Windows.Forms.Button();
            this.webBrowserShow = new System.Windows.Forms.WebBrowser();
            this.buttonClean = new System.Windows.Forms.Button();
            this.MD5 = new System.Windows.Forms.Button();
            this.RSASign = new System.Windows.Forms.Button();
            this.sm3 = new System.Windows.Forms.Button();
            this.RSAEncrypt = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // httpPost
            // 
            this.httpPost.Location = new System.Drawing.Point(134, 25);
            this.httpPost.Name = "httpPost";
            this.httpPost.Size = new System.Drawing.Size(82, 23);
            this.httpPost.TabIndex = 0;
            this.httpPost.Text = "httpPost";
            this.httpPost.TextAlign = System.Drawing.ContentAlignment.TopCenter;
            this.httpPost.UseVisualStyleBackColor = true;
            this.httpPost.Click += new System.EventHandler(this.httpPost_Click);
            // 
            // webBrowserShow
            // 
            this.webBrowserShow.Location = new System.Drawing.Point(10, 63);
            this.webBrowserShow.MinimumSize = new System.Drawing.Size(20, 20);
            this.webBrowserShow.Name = "webBrowserShow";
            this.webBrowserShow.ScriptErrorsSuppressed = true;
            this.webBrowserShow.Size = new System.Drawing.Size(620, 228);
            this.webBrowserShow.TabIndex = 6;
            // 
            // buttonClean
            // 
            this.buttonClean.Location = new System.Drawing.Point(33, 25);
            this.buttonClean.Name = "buttonClean";
            this.buttonClean.Size = new System.Drawing.Size(95, 23);
            this.buttonClean.TabIndex = 7;
            this.buttonClean.Text = "清除打印信息";
            this.buttonClean.UseVisualStyleBackColor = true;
            this.buttonClean.Click += new System.EventHandler(this.buttonClean_Click);
            // 
            // MD5
            // 
            this.MD5.Location = new System.Drawing.Point(222, 25);
            this.MD5.Name = "MD5";
            this.MD5.Size = new System.Drawing.Size(82, 23);
            this.MD5.TabIndex = 8;
            this.MD5.Text = "MD5";
            this.MD5.TextAlign = System.Drawing.ContentAlignment.TopCenter;
            this.MD5.UseVisualStyleBackColor = true;
            this.MD5.Click += new System.EventHandler(this.MD5_Click);
            // 
            // RSASign
            // 
            this.RSASign.Location = new System.Drawing.Point(310, 25);
            this.RSASign.Name = "RSASign";
            this.RSASign.Size = new System.Drawing.Size(82, 23);
            this.RSASign.TabIndex = 9;
            this.RSASign.Text = "RSA签名";
            this.RSASign.TextAlign = System.Drawing.ContentAlignment.TopCenter;
            this.RSASign.UseVisualStyleBackColor = true;
            this.RSASign.Click += new System.EventHandler(this.RSASign_Click);
            // 
            // sm3
            // 
            this.sm3.Location = new System.Drawing.Point(486, 25);
            this.sm3.Name = "sm3";
            this.sm3.Size = new System.Drawing.Size(116, 23);
            this.sm3.TabIndex = 10;
            this.sm3.Text = "国密3（SM3）加密";
            this.sm3.TextAlign = System.Drawing.ContentAlignment.TopCenter;
            this.sm3.UseVisualStyleBackColor = true;
            this.sm3.Click += new System.EventHandler(this.sm3_Click);
            // 
            // RSAEncrypt
            // 
            this.RSAEncrypt.Location = new System.Drawing.Point(398, 25);
            this.RSAEncrypt.Name = "RSAEncrypt";
            this.RSAEncrypt.Size = new System.Drawing.Size(82, 23);
            this.RSAEncrypt.TabIndex = 11;
            this.RSAEncrypt.Text = "RSA加密";
            this.RSAEncrypt.TextAlign = System.Drawing.ContentAlignment.TopCenter;
            this.RSAEncrypt.UseVisualStyleBackColor = true;
            this.RSAEncrypt.Click += new System.EventHandler(this.RSAEncrypt_Click);
            // 
            // FormTest
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(642, 303);
            this.Controls.Add(this.RSAEncrypt);
            this.Controls.Add(this.sm3);
            this.Controls.Add(this.RSASign);
            this.Controls.Add(this.MD5);
            this.Controls.Add(this.buttonClean);
            this.Controls.Add(this.webBrowserShow);
            this.Controls.Add(this.httpPost);
            this.Name = "FormTest";
            this.Text = "FormTest";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button httpPost;
        private System.Windows.Forms.WebBrowser webBrowserShow;
        private System.Windows.Forms.Button buttonClean;
        private System.Windows.Forms.Button MD5;
        private System.Windows.Forms.Button RSASign;
        private System.Windows.Forms.Button sm3;
        private System.Windows.Forms.Button RSAEncrypt;
    }
}

