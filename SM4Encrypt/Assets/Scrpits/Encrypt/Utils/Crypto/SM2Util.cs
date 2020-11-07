using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace SecretUtils.Crypto
{
    internal class SM2Util
    {
        private static readonly byte[] defaultUserID = System.Text.Encoding.ASCII.GetBytes("1234567812345678");
        /**
         * 获取der格式中的纯公钥数据
         */
        public static byte[] GetPublicKeyFormDER(byte[] derData)
        {

            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.GetInstance(derData);
            return info.PublicKeyData.GetBytes();
        }

        /**
         * 获取der编码格式中的纯私钥数据
         */
        public static byte[] GetPrivateKeyFormDER(byte[] derData)
        {

            PrivateKeyInfo pinfo = PrivateKeyInfo.GetInstance(derData);
            ECPrivateKeyStructure cpk = ECPrivateKeyStructure.GetInstance(pinfo.ParsePrivateKey());

            int length = 32;
            byte[] bytes = cpk.GetKey().ToByteArray();
            if (bytes.Length == length)
            {
                return bytes;
            }

            int start = bytes[0] == 0 ? 1 : 0;
            int count = bytes.Length - start;

            if (count > length)
            {
                throw new ArgumentException("privateKey data is error");
            }

            byte[] tmp = new byte[length];
            Buffer.BlockCopy(bytes, start, tmp, tmp.Length - count, count);
            return tmp;
        }


       
        /**
     * 生成sm2公私钥对
     * @return
     */
        public static SM2KeyPair GenerateKeyPair()
        {
            X9ECParameters sm2p256v1 = GMNamedCurves.GetByName("sm2p256v1");
            ECDomainParameters parameters = new ECDomainParameters(sm2p256v1.Curve, sm2p256v1.G, sm2p256v1.N);
            KeyGenerationParameters kgp = new ECKeyGenerationParameters(parameters, new SecureRandom());
            ECKeyPairGenerator ecKeyPairGenerator = new ECKeyPairGenerator();
            ecKeyPairGenerator.Init(kgp);
            ECPrivateKeyParameters ecpriv = null;
            ECPublicKeyParameters ecpub = null;
            //		int count = 0;
            do
            {
                AsymmetricCipherKeyPair keypair = ecKeyPairGenerator.GenerateKeyPair();
                ecpriv = (ECPrivateKeyParameters)keypair.Private;
                ecpub = (ECPublicKeyParameters)keypair.Public;
            } while (ecpriv == null || ecpriv.D.Equals(BigInteger.Zero)
                    || ecpriv.D.CompareTo(sm2p256v1.N) >= 0 || ecpriv.D.SignValue <= 0);
            byte[] privKey = FormartBigNum(ecpriv.D, 32);
            return new SM2KeyPair(privKey, ecpub.Q.GetEncoded());
        }

        /**
         * 格式化BigInteger，bg.toByteArray()获取到的字节数据长度不固定，因此需要格式化为固定长度
         * @param bg 大数
         * @param needLength 所需要的长度
         * @return
         */
        private static byte[] FormartBigNum(BigInteger bg, int needLength)
        {

            byte[] tmp = new byte[needLength];
            byte[] bgByte = bg.ToByteArray();
            if (bgByte == null)
            {
                return null;
            }

            if (bgByte.Length > needLength)
            {
                Buffer.BlockCopy(bgByte, bgByte.Length - needLength, tmp, 0, needLength);
            }
            else if (bgByte.Length == needLength)
            {
                tmp = bgByte;
            }
            else
            {
                Buffer.BlockCopy(bgByte, 0, tmp, needLength - bgByte.Length, bgByte.Length);
            }


            return tmp;
        }

        /**
         * sm2加密
         *
         */
        public static byte[] Encrypt(byte[] pubkey, byte[] srcData)
        {
            X9ECParameters sm2p256v1 = GMNamedCurves.GetByName("sm2p256v1");
            SecureRandom random = new SecureRandom();
            ECDomainParameters parameters = new ECDomainParameters(sm2p256v1.Curve, sm2p256v1.G, sm2p256v1.N);
            ECPublicKeyParameters pubKeyParameters = new ECPublicKeyParameters(sm2p256v1.Curve.DecodePoint(pubkey), parameters);
            SM2Engine engine = new SM2Engine();
            ParametersWithRandom pwr = new ParametersWithRandom(pubKeyParameters, new SecureRandom());
            engine.Init(true, pwr);
            return encodeSM2CipherToDER(engine.ProcessBlock(srcData, 0, srcData.Length));
        }

        /**
         * sm2解密
         */
        public static byte[] Decrypt(byte[] privkey, byte[] srcData)
        {
            X9ECParameters sm2p256v1 = GMNamedCurves.GetByName("sm2p256v1");
            SecureRandom random = new SecureRandom();
            ECDomainParameters parameters = new ECDomainParameters(sm2p256v1.Curve, sm2p256v1.G, sm2p256v1.N);

            ECPrivateKeyParameters priKeyParameters = new ECPrivateKeyParameters(new BigInteger(1, privkey), parameters);
            SM2Engine engine = new SM2Engine();
            ParametersWithRandom pwr = new ParametersWithRandom(priKeyParameters, new SecureRandom());
            engine.Init(false, priKeyParameters);
            byte[] c1c2c3 = decodeDERSM2Cipher(srcData);
            return engine.ProcessBlock(c1c2c3, 0, c1c2c3.Length);
        }

        /**
	 * sm2签名
	 * <p>userId使用默认：1234567812345678
	 * @param privateKey 私钥，二进制数据
	 * @param sourceData 待签名数据
	 * @return 返回der编码的签名值
	 * @throws CryptoException
	 */
        public static byte[] Sign(byte[] privateKey, byte[] sourceData)
        {
		    return Sign(defaultUserID, privateKey, sourceData);
        }

        /**
         * sm2签名
         * @param userId ID值，若无约定，使用默认：1234567812345678
         * @param privateKey 私钥，二进制数据
         * @param sourceData 待签名数据
         * @return 返回der编码的签名值
         * @throws CryptoException
         */
        public static byte[] Sign(byte[] userId, byte[] privateKey, byte[] sourceData)
        {
            X9ECParameters sm2p256v1 = GMNamedCurves.GetByName("sm2p256v1");
            ECDomainParameters parameters = new ECDomainParameters(sm2p256v1.Curve, sm2p256v1.G, sm2p256v1.N);
            ECPrivateKeyParameters priKeyParameters = new ECPrivateKeyParameters(new BigInteger(1,privateKey),parameters);
            SM2Signer signer = new SM2Signer();
            ICipherParameters param = null;
            ParametersWithRandom pwr = new ParametersWithRandom(priKeyParameters, new SecureRandom());
        if (userId != null) {
                param = new ParametersWithID(pwr, userId);
            } else {
                param = pwr;
            }
            signer.Init(true, param);
            signer.BlockUpdate(sourceData, 0, sourceData.Length);
        return signer.GenerateSignature();
        }

        /**
         * sm2验签
         * <p>userId使用默认：1234567812345678
         * @param publicKey 公钥，二进制数据
         * @param sourceData 待验签数据
         * @param signData 签名值
         * @return 返回是否成功
         */
        public static Boolean VerifySign(byte[] publicKey, byte[] sourceData, byte[] signData)
        {
            return VerifySign(defaultUserID, publicKey, sourceData, signData);
        }

        /**
         * sm2验签
         * @param userId ID值，若无约定，使用默认：1234567812345678
         * @param publicKey 公钥，二进制数据
         * @param sourceData 待验签数据
         * @param signData 签名值
         * @return 返回是否成功
         */
        public static Boolean VerifySign(byte[] userId, byte[] publicKey, byte[] sourceData, byte[] signData)
        {

            if (publicKey.Length == 64)
            {
                byte[] tmp = new byte[65];
                Buffer.BlockCopy(publicKey, 0, tmp, 1, publicKey.Length);
                tmp[0] = 0x04;
                publicKey = tmp;
            }

            X9ECParameters sm2p256v1 = GMNamedCurves.GetByName("sm2p256v1");
            ECDomainParameters parameters = new ECDomainParameters(sm2p256v1.Curve, sm2p256v1.G, sm2p256v1.N);
            ECPublicKeyParameters pubKeyParameters = new ECPublicKeyParameters(sm2p256v1.Curve.DecodePoint(publicKey), parameters);
            SM2Signer signer = new SM2Signer();
            ICipherParameters param;
            if (userId != null)
            {
                param = new ParametersWithID(pubKeyParameters, userId);
            }
            else
            {
                param = pubKeyParameters;
            }
            signer.Init(false, param);
            signer.BlockUpdate(sourceData, 0, sourceData.Length);
            return signer.VerifySignature(signData);
        }

        public static byte[] encodeSM2CipherToDER(byte[] cipher)
        {
            int startPos = 1;

            int curveLength = 32;
            int digestLength = 32;

            byte[] c1x = new byte[curveLength];
            Buffer.BlockCopy(cipher, startPos, c1x, 0, c1x.Length);
            startPos += c1x.Length;

            byte[] c1y = new byte[curveLength];
            Buffer.BlockCopy(cipher, startPos, c1y, 0, c1y.Length);
            startPos += c1y.Length;

            byte[] c2 = new byte[cipher.Length - c1x.Length - c1y.Length - 1 - digestLength];
            Buffer.BlockCopy(cipher, startPos, c2, 0, c2.Length);
            startPos += c2.Length;

            byte[] c3 = new byte[digestLength];
            Buffer.BlockCopy(cipher, startPos, c3, 0, c3.Length);

            Asn1Encodable[] arr = new Asn1Encodable[4];
            arr[0] = new DerInteger(new BigInteger(1, c1x));//
            arr[1] = new DerInteger(new BigInteger(1, c1y));//
            arr[2] = new DerOctetString(c3);
            arr[3] = new DerOctetString(c2);
            DerSequence ds = new DerSequence(arr);
            return ds.GetEncoded(Asn1Encodable.Der);
        }

        public static byte[] decodeDERSM2Cipher(byte[] derCipher)
        {
            Asn1Sequence ds = DerSequence.GetInstance(derCipher);
            byte[] c1x = ((DerInteger)ds[0]).Value.ToByteArray();
            byte[] c1y = ((DerInteger)ds[1]).Value.ToByteArray();
            byte[] c3 = ((DerOctetString)ds[2]).GetOctets();
            byte[] c2 = ((DerOctetString)ds[3]).GetOctets();

            int pos = 0;
            int cureLength = 32;
            byte[] cipherText = new byte[1 + c2.Length + cureLength * 2 + c3.Length];

            byte uncompressedFlag = 0x04;
            cipherText[0] = uncompressedFlag;
            pos += 1;

            if (c1x.Length >= cureLength)
            {
                Buffer.BlockCopy(c1x, c1x.Length - cureLength, cipherText, pos, cureLength);
            }
            else
            {
                Buffer.BlockCopy(c1x, 0, cipherText, pos + cureLength - c1x.Length, c1x.Length);
            }
            pos += cureLength;

            if (c1y.Length >= cureLength)
            {
                Buffer.BlockCopy(c1y, c1y.Length - cureLength, cipherText, pos, cureLength);
            }
            else
            {
                Buffer.BlockCopy(c1y, 0, cipherText, pos + cureLength - c1y.Length, c1y.Length);
            }
            pos += cureLength;

            Buffer.BlockCopy(c2, 0, cipherText, pos, c2.Length);
            pos += c2.Length;

            Buffer.BlockCopy(c3, 0, cipherText, pos, c3.Length);

            return cipherText;
        }

    }
}
