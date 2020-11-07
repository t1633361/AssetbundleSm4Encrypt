using System.Security.Cryptography;

namespace SecretUtils.Crypto
{
    public class MD5Util
    {
        public static string GetMD5(byte[] inputBye, string charset)
        {
            string retStr;
            MD5CryptoServiceProvider m5 = new MD5CryptoServiceProvider();

            //创建md5对象
            //byte[] inputBye;
            byte[] outputBye;

            ////使用GB2312编码方式把字符串转化为字节数组．
            //try
            //{
            //    inputBye = Encoding.GetEncoding(charset).GetBytes(encypStr);
            //}
            //catch (Exception ex)
            //{
            //    inputBye = Encoding.GetEncoding("GB2312").GetBytes(encypStr);
            //    Console.WriteLine(ex);
            //}
            outputBye = m5.ComputeHash(inputBye);
            //retStr= Base64.ToBase64String(outputBye);
            retStr = System.BitConverter.ToString(outputBye);
            retStr = retStr.Replace("-", "").ToUpper();
            return retStr;
        }
    }
}
