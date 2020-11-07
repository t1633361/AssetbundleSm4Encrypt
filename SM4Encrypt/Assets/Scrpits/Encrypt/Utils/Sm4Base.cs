using Org.BouncyCastle.Utilities.Encoders;
using SecretUtils.Crypto;

namespace SecretUtils
{
    public class Sm4Base
    {   
        /// <summary>
        /// 生成SM4 byte Key
        /// </summary>
        /// <returns></returns>
        public static byte[] GenerateKey()
        {
            byte[] sm4key=  SM4Util.GenerateKey(SM4Util.SM4_KEY_128);
            return sm4key;
        }
        /// <summary>
        /// 生成SM4 string Key
        /// </summary>
        /// <returns></returns>
        public static string GenerateKeyString()
        {
            byte[] sm4key = SM4Util.GenerateKey(SM4Util.SM4_KEY_128);
         
            return Hex.ToHexString(sm4key, 0, sm4key.Length);
        }

        /// <summary>
        /// CBC模式加密
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] EncryptCBC(byte[] data,string key)
        {
            byte[] cipher = SM4Util.EncryptCBC(data, Hex.Decode(key), Hex.Decode(key));
            return cipher;
        }
        /// <summary>
        /// CBC模式加密
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] EncryptCBCNoPadding(byte[] data, string key)
        {
            byte[] cipher = SM4Util.EncryptCBC(data, Hex.Decode(key), Hex.Decode(key), 0);
            return cipher;
        }
        
        /// <summary>
        /// CBC模式解密
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] DecryptCBC(byte[] data,string key)
        {
            byte[] plain = SM4Util.DecryptCBC(data, Hex.Decode(key), Hex.Decode(key));
            return plain;
        }
        /// <summary>
        /// CBC模式解密
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] DecryptCBCNoPadding(byte[] data, string key)
        {
            byte[] plain = SM4Util.DecryptCBC(data, Hex.Decode(key), Hex.Decode(key), 0);
            return plain;
        }
    }
}
