using System;
using Org.BouncyCastle.Crypto.Digests;

namespace SecretUtils.Crypto
{
    /**
     * 计算sm3 hash值
     * <p>若无特殊说明，接口接收的都是原始的二进制数据，被hex或者base64编码的数据，务必解码之后再传进来
     * @author liangruxing
     *
     */
    class SM3Util
    {
        /**
	 * 计算hash值，在数据量不大时使用，数据量大应使用原生接口，分段计算sm3值
	 * @param srcData 待计算hash值的数据
	 * @return
	 */
        public static byte[] Hash(byte[] srcData)
        {
            SM3Digest digest = new SM3Digest();
            digest.BlockUpdate(srcData, 0, srcData.Length);
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);
            return hash;
        }

        /**
         * 校验sm3值，在数据量不大时使用，数据量大应使用原生接口，分段计算sm3值，然后校验
         * @param srcData 待验证的数据
         * @param sm3Hash 待验证的hash值
         * @return
         */
        public static Boolean VerifyHash(byte[] srcData, byte[] sm3Hash)
        {
            byte[] newHash = Hash(srcData);
            if (newHash.Length != sm3Hash.Length) {
                return false;
            }
            for (int i = 0;i< newHash.Length;i++) {
                if (newHash[i] != sm3Hash[i]) {
                    return false;
                }
            }
            return true;
        }
    }
}
