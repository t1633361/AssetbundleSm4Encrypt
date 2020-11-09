namespace Encrypt
{
    public static class Sm4Define
    {
        public const string key             = "7c93d3aaa0ea5c91b6d426f99ac0951a";
        public const int    segmentSize     = 32 * 1024;
        public const int    segmentSizeSub1 = segmentSize - 1;
        public const bool   encryptHeader   = false;
    }
}