namespace SecretUtils.Crypto
{
    public class SM2KeyPair
    {
        public byte[] priKey;//私钥
        public byte[] pubKey;//公钥
        public SM2KeyPair(byte[] priKey, byte[] pubKey) {
            this.priKey = priKey;
            this.pubKey = pubKey;
        }
        
    }
}
