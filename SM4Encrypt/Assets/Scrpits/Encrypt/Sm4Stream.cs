using System.IO;
using SecretUtils;

namespace Encrypt
{
    public class Sm4Stream : FileStream
    {
        const   byte   KEY    = 64;
        private string sm4key = Sm4Define.key;
        public Sm4Stream(string path, FileMode mode, FileAccess access, FileShare share, int bufferSize, bool useAsync) : base(path, mode, access, share, bufferSize, useAsync)
        {
        }
        public Sm4Stream(string path, FileMode mode) : base(path, mode)
        {
        }
    
        public override int Read(byte[] array, int offset, int count)
        {
            var index = base.Read(array, offset, count);
       
            var sm4 = Sm4Base.DecryptCBCNoPadding(array, sm4key);
        
            array = (byte [])sm4.Clone();
        
            return array.Length;
        }
        public override void Write(byte[] array, int offset, int count)
        {
            for (int i = 0; i < array.Length; i++)
            {
                array[i] ^= KEY;
            }
            base.Write(array, offset, count);
        }
    
    
    }
}