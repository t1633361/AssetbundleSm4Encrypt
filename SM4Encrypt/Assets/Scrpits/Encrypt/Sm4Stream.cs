using System;
using System.Collections.Generic;
using System.IO;
using SecretUtils;
using Test;
using UnityEngine;

namespace Encrypt
{
    public class Sm4Stream : FileStream
    {
        private readonly string sm4key;
        public override  bool   CanRead => true;
        public override  bool   CanSeek => true;
        
        public Sm4Stream(string path, FileMode mode, string key) : base(path, mode)
        {
            sm4key = key;
        }

        public Sm4Stream(string path, FileMode mode, FileAccess access, FileShare share, int bufferSize, bool useAsync,string key) : base(path, mode, access, share, bufferSize, useAsync)
        {
            sm4key = key;
        }

        private byte[] _lz4Cache;
        public override int Read(byte[] array, int offset, int count)
        {
            
            if(offset != 0)
                throw new EncryptException($"Offset is {offset}");

            long  index       = -1;
            long remainder = Position % count;

            if (Sm4Define.encryptAll)
            {
                if (remainder == 0)
                {
                    index = base.Read(array, offset, count);
                    DecryptRead(array, index);
                }
                else
                {
                    long oldPos   = Position;
                    
                    long firstPos = oldPos - remainder;
                    
                    long secondPos  = firstPos + count;
                    
                    if (Length < secondPos)
                    {
                        base.Seek(firstPos, SeekOrigin.Begin);
                        
                        if(_lz4Cache == null || _lz4Cache.Length != count)
                            _lz4Cache = new byte[count];
                        
                        int firstIndex = base.Read(_lz4Cache, offset, count);
                        
                        var sm4 = Sm4Base.DecryptCBCNoPadding(_lz4Cache, sm4key);
                        
                        for (long i = remainder; i < firstIndex; ++i)
                        {
                            array[i - remainder] = sm4[i];
                        }

                        index = firstIndex - remainder;
                    }
                    else
                    {
                        base.Seek(firstPos, SeekOrigin.Begin);
                        
                        if(_lz4Cache == null || _lz4Cache.Length != count)
                            _lz4Cache = new byte[count];
                        
                        base.Read(_lz4Cache, offset, count);
                        
                        var sm4 = Sm4Base.DecryptCBCNoPadding(_lz4Cache, sm4key);

                        base.Read(_lz4Cache, offset, count);
                        
                        var sm41 = Sm4Base.DecryptCBCNoPadding(_lz4Cache, sm4key);

                        for (long i = remainder; i < count; ++i)
                        {
                            array[i - remainder] = sm4[i];
                        }
                        
                        for (int i = 0; i < remainder; ++i)
                        {
                            array[count - remainder + i] = sm41[i];
                        }
                        base.Seek(oldPos + count, SeekOrigin.Begin);
                        index = count;
                    }
                }
            }
            else
            {
                if (remainder == 0)
                {
                    bool header = Position == 0;

                    if (header)
                    {
                        DecryptRead(array, index);
                    }
                }
                else
                {
                    
                }
            }

            return (int)index;
        }

        private void DecryptRead(byte[] array, long index)
        {
            var sm4 = Sm4Base.DecryptCBCNoPadding(array, sm4key);

            for (int i = 0; i < index; ++i)
            {
                array[i] = sm4[i];
            }
        }

        private void EncryptAllRead()
        {
            
        }

        private void EncryptHeaderRead()
        {
            
        }
        public override void Write(byte[] array, int offset, int count)
        {
            throw new NotImplementedException();
        }
    
    
    }
}