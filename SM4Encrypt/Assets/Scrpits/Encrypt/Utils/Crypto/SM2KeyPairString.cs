using Org.BouncyCastle.Utilities.Encoders;

namespace SecretUtils.Crypto
{
    public class SM2KeyPairString
    {
        public string priKey;//私钥
        public string pubKey;//公钥
        public SM2KeyPairString(SM2KeyPair sm2Key)
        {
            this.priKey =Hex.ToHexString(sm2Key.priKey,0, sm2Key.priKey.Length);
            this.pubKey = Hex.ToHexString(sm2Key.pubKey, 0, sm2Key.pubKey.Length);
        }

    }
}
