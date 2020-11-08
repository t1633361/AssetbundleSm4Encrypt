using System;
using System.IO;
using SecretUtils;
using UnityEngine;

namespace Encrypt
{
    public class Sm4Stream : FileStream
    {
        private readonly string sm4key;
        public Sm4Stream(string path, FileMode mode, FileAccess access, FileShare share, int bufferSize, bool useAsync,string key) : base(path, mode, access, share, bufferSize, useAsync)
        {
            sm4key = key;
        }
        public Sm4Stream(string path, FileMode mode,string key) : base(path, mode)
        {
            sm4key = key;
        }
    
        public override int Read(byte[] array, int offset, int count)
        {
            
            var index = base.Read(array, offset, count);
       
            var sm4 = Sm4Base.DecryptCBCNoPadding(array, sm4key);

            for (int i = 0; i < index; ++i)
            {
                array[i] = sm4[i];
            }
        
            return index;
        }
        public override void Write(byte[] array, int offset, int count)
        {
            throw new NotImplementedException();
        }
    
    
    }
}