using System;
using System.IO;
using SecretUtils;

namespace Encrypt
{
    public class Sm4Stream : FileStream
    {
        private readonly string sm4key;
        public override  bool   CanRead => true;
        public override  bool   CanSeek => true;

        private bool _encryptAll;

        public Sm4Stream(string path, FileMode mode, string key, bool encryptAll = false) : base(path, mode)
        {
            sm4key      = key;
            _encryptAll = encryptAll;
        }

        public Sm4Stream(string path, FileMode mode, FileAccess access, FileShare share, int bufferSize, bool useAsync,
            string              key,  bool encryptAll = false) : base(path, mode, access, share, bufferSize, useAsync)
        {
            sm4key      = key;
            _encryptAll = encryptAll;
        }

        private byte[] _headerCache;
        private byte[] _byteCache;

        public override int Read(byte[] array, int offset, int count)
        {
            if (offset != 0)
                throw new EncryptException($"Offset is {offset}");

            long index     = -1;
            long remainder = Position % count;

            if (Sm4Define.encryptAll)
            {
                if (remainder == 0)
                {
                    index = DecryptSegment(array, count, count - remainder, 0, remainder);
                }
                else
                {
                    long oldPos = Position;

                    long firstPos = oldPos - remainder;

                    long secondPos = firstPos + count;

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
                        if (_headerCache == null)
                        {
                            DecryptHeader(count);
                        }

                        Array.Copy(_headerCache, 0, array, 0, _headerCache.Length);
                        index = _headerCache.Length;
                        base.Seek(index, SeekOrigin.Begin);
                    }
                    else
                    {
                        index = Decrypt(array, count);
                    }
                }
                else
                {
                    if (_headerCache == null)
                        throw new EncryptException("Don't decrypt header.");

                    if (Length < count)//file size less than segment size 
                    {
                        index = _headerCache.Length - Position;
                        Array.Copy(_headerCache, Position, array, 0, index);
                    }
                    else if (Position < count)
                    {
                        long oldPos = Position;

                        var leftLength = count - remainder;
                        
                        base.Seek(count, SeekOrigin.Begin);
                        
                        index = base.Read(array, 0, count);
                        index = Math.Min(index, remainder);

                        for (int i = 0; i < index; ++i) // Decrypt
                        {
                            array[i + (leftLength)] = array[i];
                        }

                        Array.Copy(_headerCache, remainder, array, 0, leftLength);
                        
                        index = leftLength + index;
                        
                        base.Seek(oldPos + index, SeekOrigin.Begin);
                    }
                    else
                    {
                        index = Decrypt(array, count);    
                    }
                }
            }

            return (int) index;
        }

        private int DecryptHeader(int segmentSize)
        {
            long oldPos = Position;
            segmentSize = (int)Math.Min(segmentSize, Length);
            
            if (_byteCache == null || _byteCache.Length != segmentSize)
                _byteCache = new byte[segmentSize];

            var index = base.Read(_byteCache, 0, segmentSize);
            _headerCache = Sm4Base.DecryptCBCNoPadding(_byteCache, sm4key);

            base.Seek(oldPos, SeekOrigin.Begin);
            
            return index;
        }

        private int Decrypt(byte[] array, int segmentSize)
        {
            var index = base.Read(array, 0, segmentSize);

            return index;
        }

        private int DecryptSegment(byte[] array, int segmentSize, long copyLength, long sourceOffset,
            long                          decryptOffset)
        {
            if (_byteCache == null || _byteCache.Length != segmentSize)
                _byteCache = new byte[segmentSize];

            var index = base.Read(_byteCache, 0, segmentSize);
            var sm4   = Sm4Base.DecryptCBCNoPadding(_byteCache, sm4key);

            var offsetLenght = index - decryptOffset;
            var minLength    = Math.Min(copyLength, offsetLenght);
            for (long i = 0; i < minLength; ++i)
            {
                array[i + sourceOffset] = sm4[i + decryptOffset];
            }

            return (int) offsetLenght;
        }

        public override void Write(byte[] array, int offset, int count)
        {
            throw new NotImplementedException();
        }
    }
}