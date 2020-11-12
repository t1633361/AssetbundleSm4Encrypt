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

        private bool _encryptAll;
        
        public Sm4Stream(string path, FileMode mode, string key, bool encryptAll=false) : base(path, mode)
        {
            sm4key      = key;
            _encryptAll = encryptAll;
        }

        public Sm4Stream(string path, FileMode mode, FileAccess access, FileShare share, int bufferSize, bool useAsync,string key, bool encryptAll=false) : base(path, mode, access, share, bufferSize, useAsync)
        {
            sm4key      = key;
            _encryptAll = encryptAll;
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
                    index = DecryptSegment(array, count, count - remainder, 0, remainder);
                }
                else
                {
                    long oldPos   = Position;
                    
                    long firstPos = oldPos - remainder;
                    
                    long secondPos  = firstPos + count;
                    
                    base.Seek(firstPos, SeekOrigin.Begin);
                    
                    if (Length < secondPos)
                    {
                        index = DecryptSegment(array, count, count - remainder, 0, remainder);
                    }
                    else
                    {
                        DecryptSegment(array, count, count - remainder, 0, remainder);

                        DecryptSegment(array, count, remainder, count - remainder, 0);

                        index = count;
                    }
                    base.Seek(oldPos + index, SeekOrigin.Begin);
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
        
        private int DecryptSegment(byte[] array, int segmentSize, long copyLength, long sourceOffset,  long decryptOffset)
        {
            if (_lz4Cache == null || _lz4Cache.Length != segmentSize)
                _lz4Cache = new byte[segmentSize];

            var index = base.Read(_lz4Cache, 0, segmentSize);

            var offsetLenght = index - decryptOffset;
            var l1 = copyLength > offsetLenght ? offsetLenght : copyLength;

            var sm4 = Sm4Base.DecryptCBCNoPadding(_lz4Cache, sm4key);

            for (long i = 0; i < l1; ++i)
            {
                array[i + sourceOffset] = sm4[i+decryptOffset];
            }

            return (int)offsetLenght;
        }

        private void DecryptRead(byte[] array, long index)
        {
            var sm4 = Sm4Base.DecryptCBCNoPadding(array, sm4key);

            for (int i = 0; i < index; ++i)
            {
                array[i] = sm4[i];
            }
        }
        
        public override void Write(byte[] array, int offset, int count)
        {
            throw new NotImplementedException();
        }
    
    
    }
}