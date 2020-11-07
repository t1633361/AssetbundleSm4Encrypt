using System.IO;
using Org.BouncyCastle.Utilities.Encoders;
using SecretUtils.Crypto;

namespace SecretUtils
{
    public class Sm2Base
    {   
        /// <summary>
        /// 生成SM2 byte Key
        /// </summary>
        /// <returns></returns>
        public static SM2KeyPair GenerateKey()
        {
            SM2KeyPair keys = SM2Util.GenerateKeyPair();
            return keys;
        }
        /// <summary>
        /// 生成SM2 string Key
        /// </summary>
        /// <returns></returns>
        public static SM2KeyPairString GenerateKeyString()
        {
            return new SM2KeyPairString(SM2Util.GenerateKeyPair());
        }
        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="pubkey">公钥</param>
        /// <param name="data">数据</param>
        /// <returns></returns>
        public static byte[] Encrypt(string pubkey, byte[] data)
        {
            byte[] cipher = SM2Util.Encrypt(Hex.Decode(pubkey), data);
            return cipher;
        }
        public static byte[] Encrypt(byte[] pubkey, byte[] data)
        {
            byte[] cipher = SM2Util.Encrypt(pubkey, data);
            return cipher;
        }
        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="privkey">私钥</param>
        /// <param name="data">数据</param>
        /// <returns></returns>
        public static byte[] Decrypt(string privkey, byte[] data)
        {
            byte[] plain = SM2Util.Decrypt(Hex.Decode(privkey), data);
            return plain;
        }
        public static byte[] Decrypt(byte[] privkey, byte[] data)
        {
            byte[] plain = SM2Util.Decrypt(privkey, data);
            return plain;
        }
        /// <summary>
        /// 签名
        /// </summary>
        /// <returns></returns>
        public static byte[] Sign(byte[] privateKey, byte[] data)
        {
            byte[] signByte= SM2Util.Sign(privateKey, data);
            return signByte;
        }

        public static byte[] Sign(string privateKey, byte[] data)
        {
            byte[] signByte = SM2Util.Sign(Hex.Decode(privateKey), data);
            return signByte;
        }
        /// <summary>
        /// 验签
        /// </summary>
        /// <returns></returns>
        public static bool VerifySign(byte[] publicKey, byte[] data, byte[] signData)
        {
            bool b= SM2Util.VerifySign(publicKey, data, signData);
            return b;
        }
        public static bool VerifySign(string publicKey, byte[] data, byte[] signData)
        {
            bool b = SM2Util.VerifySign(Hex.Decode(publicKey), data, signData);
            return b;
        }
        /// <summary>
        /// 秘钥文件生成
        /// </summary>
        /// <param name="keyData"></param>
        /// <param name="path"></param>
        public static void GenerateKeyFile(byte[] keyData,string path)
        {
            FileStream fs = new FileStream(path, FileMode.Create);
            BinaryWriter bw = new BinaryWriter(fs);
            bw.Write(keyData);
            bw.Close();
            fs.Close();
        }
        public static void GenerateKeyFile(string keyData, string path)
        {
            byte[] keyBytes = Hex.Decode(keyData);
            FileStream fs = new FileStream(path, FileMode.Create);
            BinaryWriter bw = new BinaryWriter(fs);
            bw.Write(keyBytes);
            bw.Close();
            fs.Close();
        }
        /// <summary>
        /// 秘钥加载读取
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        public static byte[] LoadKeyFileBytes(string filePath)
        {
            FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read);
            byte[] buffur = new byte[fs.Length];
            fs.Read(buffur, 0, (int)fs.Length);
            return buffur;
        }
        public static string LoadKeyFileString(string filePath)
        {
            FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read);
            byte[] buffur = new byte[fs.Length];
            fs.Read(buffur, 0, (int)fs.Length);
            return Hex.ToHexString(buffur);
        }
    }
}
