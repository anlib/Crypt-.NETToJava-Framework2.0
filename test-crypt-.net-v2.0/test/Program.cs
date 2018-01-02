using System;
using System.Collections.Generic;
using System.Windows.Forms;
using Test;

namespace Test
{
    static class Program
    {
        /// <summary>
        /// 应用程序的主入口点
        /// </summary>      
        /// <remarks>
        /// 2017.12.01: 创建. 李兵 <br/>
        /// </remarks>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new FormTest());
        }
    }
}
