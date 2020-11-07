using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace SecretUtils.Crypto
{
    /**
     * sm4加解密工具类
     * <p>因为数据加解密都是对字节数据加解密，因此需要注意加密前和解密后使用的字符集保持一致
     * <p>若无特殊说明，接口接收的都是原始的二进制数据，被hex或者base64编码的数据，务必解码之后再传入接口
     * @author liangruxing
     *
     */
    internal class SM4Util
    {
        private const int SM4_ENCRYPT = 1;
        private const int SM4_DECRYPT = 0;
        public const int SM4_PKCS7PADDING = 1;
        public const int SM4_NOPADDING = 0;
        public const int SM4_KEY_128 = 128;
      
        private const String iv = "DB4433CBE745731BBFA534109636F5FD";
        /// <summary>
        /// 使用国密SM4对文本加密字符串
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string SM4EncryptData(string key, byte[] dataBytes)
        {
            
            //byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            byte[] cipher = SM4Util.EncryptCBC(dataBytes, Hex.Decode(key), Hex.Decode(key));
            return Convert.ToBase64String(cipher);
        }

        public static string SM4DecryptData(string key,string data)
        {
            byte[] cipher = Convert.FromBase64String(data);
            byte[] plain = SM4Util.DecryptCBC(cipher, Hex.Decode(key), Hex.Decode(key));
            return Hex.ToHexString(cipher, 0, cipher.Length);
        }

        /**
         * 生成sm4密钥，长度使用
         * @param keySize 密钥位数（通过SM4Util的常量获取长度值）
         * @return sm4密钥
         */
        public static byte[] GenerateKey(int keySize)
        {
            byte[] key = new byte[keySize / 8];
            SecureRandom sr = new SecureRandom();
            sr.NextBytes(key);

            return key;
        }

        /**
         * sm4 ecb模式加密数据，数据长度非16倍数，则使用默认PKCS7PADDING方式填充
         * @param data 待加密的数据
         * @param key sm4密钥
         * @return 密文数据
         */
        public static byte[] EncryptECB(byte[] data, byte[] key)
        {
            return EncryptECB(data, key, SM4_PKCS7PADDING);
        }

        /**
         * sm4 ecb模式解密数据，使用默认PKCS7PADDING方式去除填充
         * @param cipher 密文数据
         * @param key sm4密钥
         * @return 明文字节数据
         */
        public static byte[] DecryptECB(byte[] cipher, byte[] key)
        {
            return DecryptECB(cipher, key, SM4_PKCS7PADDING);
        }

        /**
         * sm4 CBC模式加密数据，数据长度非16倍数，则使用默认PKCS7PADDING方式填充
         * @param data 待加密数据
         * @param key sm4密钥
         * @param iv 向量
         * @return 密文数据
         */
        public static byte[] EncryptCBC(byte[] data, byte[] key, byte[] iv)
        {
            return EncryptCBC(data, key, iv, SM4_PKCS7PADDING);
        }

        /**
         * sm4 cbc模式解密数据，使用默认PKCS7PADDING方式去除填充
         * @param cipher sm4密文数据
         * @param key sm4密钥
         * @param iv 向量
         * @return 明文字节数据
         */
        public static byte[] DecryptCBC(byte[] cipher, byte[] key, byte[] iv)
        {
            return DecryptCBC(cipher, key, iv, SM4_PKCS7PADDING);
        }

        /**
         * sm4 ecb模式加密数据
         * @param data 待加密数据
         * @param key sm4密钥
         * @param paddingMode 填充模式，具体支持请看类的常量字段,若使用不支持的模式则会默认无填充
         * @return 返回密文数据
         */
        public static byte[] EncryptECB(byte[] data, byte[] key, int paddingMode)
        {
            IBlockCipher engine = new SM4Engine();
            engine.Init(true, new KeyParameter(key));
            if (paddingMode == SM4_PKCS7PADDING)
            {
                data = padding(data, SM4_ENCRYPT);
            }
            else
            {
                data = (byte [])data.Clone();
            }
            int length = data.Length;
            for (int i = 0; length > 0; length -= 16, i += 16)
            {
                engine.ProcessBlock(data, i, data, i);
            }
            return data;
        }

        /**
         * sm4 ecb模式解密数据
         * @param cipher 密文数据
         * @param key sm4密钥
         * @param paddingMode 填充模式，具体支持请看类的常量字段,若使用不支持的模式则会默认无填充
         * @return 返回明文字节数据
         */
        public static byte[] DecryptECB(byte[] cipher, byte[] key, int paddingMode)
        {
            IBlockCipher engine = new SM4Engine();
            engine.Init(false, new KeyParameter(key));
            int length = cipher.Length;
            byte[] tmp = new byte[cipher.Length];
            for (int i = 0; length > 0; length -= 16, i += 16)
            {
                engine.ProcessBlock(cipher, i, tmp, i);
            }
            byte[] plain = null;
            if (paddingMode == SM4_PKCS7PADDING)
            {
                plain = padding(tmp, SM4_DECRYPT);
            }
            else
            {
                plain = tmp;
            }
            return plain;
        }

        /**
         * CBC模式加密数据
         * @param data 待加密数据
         * @param key 密钥
         * @param iv 向量
         * @param paddingMode 填充模式，具体支持请看类的常量字段,若使用不支持的模式则会默认无填充
         * @return 返回密文值
         */
        public static byte[] EncryptCBC(byte[] data, byte[] key, byte[] iv, int paddingMode)
        {
            IBlockCipher engine = new SM4Engine();
            engine.Init(true, new KeyParameter(key));
            if (paddingMode == SM4_PKCS7PADDING)
            {
                data = padding(data, SM4_ENCRYPT);
            }
            else
            {
                data = (byte [])data.Clone();
            }
            int length = data.Length;
            iv = (byte [])iv.Clone();
            for (int i = 0; length > 0; length -= 16, i += 16)
            {

                for (int j = 0; j < 16; j++)
                {
                    try
                    {
                        data[i + j] = ((byte)(data[i + j] ^ iv[j]));
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                        throw;
                    }
                    
                }
                engine.ProcessBlock(data, i, data, i);
                Buffer.BlockCopy(data, i, iv, 0, 16);
            }
            return data;
        }

        /**
         * CBC模式解密数据
         * @param cipher 密文数据
         * @param key 密钥
         * @param iv 向量
         * @param isPadding 填充模式，具体支持请看类的常量字段,若使用不支持的模式则会默认无填充
         * @return 返回明文字节数据
         */
        public static byte[] DecryptCBC(byte[] cipher, byte[] key, byte[] iv, int paddingMode)
        {
            IBlockCipher engine = new SM4Engine();
            engine.Init(false, new KeyParameter(key));
            int length = cipher.Length;
            byte[] plain = new byte[cipher.Length];
            iv = (byte [])iv.Clone();
            for (int i = 0; length > 0; length -= 16, i += 16)
            {

                engine.ProcessBlock(cipher, i, plain, i);
                for (int j = 0; j < 16; j++)
                {
                    plain[j + i] = ((byte)(plain[i + j] ^ iv[j]));
                }
                Buffer.BlockCopy(cipher, i, iv, 0, 16);
            }

            byte[] res = null;
            if (paddingMode == SM4_PKCS7PADDING)
            {
                res = padding(plain, SM4_DECRYPT);
            }
            else
            {
                res = plain;
            }
            return res;
        }


       
        /**
         * PKCS7PADDING标准填充
         * @param input 输入数据
         * @param mode 填充或去除填充
         * @return
         */
        private static byte[] padding(byte[] input, int mode)
        {
            if (input == null)
            {
                return null;
            }

            byte[] ret = (byte[])null;
            if (mode == SM4_ENCRYPT)
            {
                int p = 16 - input.Length % 16;
                ret = new byte[input.Length + p];
                Buffer.BlockCopy(input, 0, ret, 0, input.Length);
                for (int i = 0; i < p; i++)
                {
                    ret[input.Length + i] = (byte)p;
                }
            }
            else
            {
                int p = input[input.Length - 1];
                ret = new byte[input.Length - p];
                Buffer.BlockCopy(input, 0, ret, 0, input.Length - p);
            }
            return ret;
        }
    }
}
