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
        private readonly string     sm4key;
        private          FileStream testStream;
        public Sm4Stream(string path, FileMode mode, FileAccess access, FileShare share, int bufferSize, bool useAsync,string key) : base(path, mode, access, share, bufferSize, useAsync)
        {
            sm4key = key;
            
            var assetPath = String.Format("{0}/{1}_p.{2}", Application.streamingAssetsPath, TestDefine.sceneName_lz4,
                TestDefine.scenePostfix);
            
            testStream = new FileStream(assetPath, FileMode.Open);
            
        }

        public override bool CanRead => true;
        public override bool CanSeek => true;

        public Sm4Stream(string path, FileMode mode,string key) : base(path, mode)
        {
            sm4key = key;
            
            var assetPath = String.Format("{0}/{1}_p.{2}", Application.streamingAssetsPath, TestDefine.sceneName_lz4,
                TestDefine.scenePostfix);
            
            testStream = new FileStream(assetPath, FileMode.Open);
        }
        public Dictionary<long, byte[]> tempBytes = new Dictionary<long, byte[]>();

        private byte[] lz4Cache;
        public override int Read(byte[] array, int offset, int count)
        {
            Debug.LogFormat("Read:{0} {1}",Position,count);
            
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
                        
                        if(lz4Cache == null || lz4Cache.Length != count)
                            lz4Cache = new byte[count];
                        
                        int firstIndex = base.Read(lz4Cache, offset, count);
                        
                        var sm4 = Sm4Base.DecryptCBCNoPadding(lz4Cache, sm4key);
                        
                        index = firstIndex - remainder;
                        
                        for (long i = remainder; i < firstIndex; ++i)
                        {
                            array[i - remainder] = sm4[i];
                        }
                        
                        testStream.Seek(oldPos, SeekOrigin.Begin);
                        int lz4Index = testStream.Read(sm4, offset, count);
                        
                        Debug.LogFormat("SeekPos:{0} {1} {2}", testStream.Position, Position, lz4Index);
                        
                        index = lz4Index;
                        
                        for (int i = 0; i < count; ++i)
                        {
                            sm4[i] = array[i];
                        }
                        
                        tempBytes[oldPos] = sm4;
                        
                        // testStream.Seek(Position, SeekOrigin.Begin);
                        // index = base.Read(array, offset, count);
                        // index = testStream.Read(array, offset, count);
                        // Debug.LogFormat("Read:{0} {1} {2} {3}", testStream.Position, Position, count, index);
                        // return (int)index;
                    }
                    else
                    {
                        // testStream.Seek(Position, SeekOrigin.Begin);
                        // index = base.Read(array, offset, count);
                        // index = testStream.Read(array, offset, count);
                        // Debug.LogFormat("Read:{0} {1} {2} {3}", testStream.Position, Position, count, index);
                        // return (int)index;
                        
                        base.Seek(firstPos, SeekOrigin.Begin);
                        
                        if(lz4Cache == null || lz4Cache.Length != count)
                            lz4Cache = new byte[count];
                        
                        int firstIndex = base.Read(lz4Cache, offset, count);
                        
                        var sm4 = Sm4Base.DecryptCBCNoPadding(lz4Cache, sm4key);
                        
                        
                        //base.Seek(secondPos, SeekOrigin.Begin);
                        
                        int secondIndex = base.Read(lz4Cache, offset, count);
                        
                        var sm41 = Sm4Base.DecryptCBCNoPadding(lz4Cache, sm4key);
                        
                        for (int i = 0; i < count; ++i)
                        {
                            array[i] = 0;
                        }
                        
                        for (long i = remainder; i < count; ++i)
                        {
                            array[i - remainder] = sm4[i];
                        }
                        
                        for (int i = 0; i < remainder; ++i)
                        {
                            array[count - remainder + i] = sm41[i];
                        }

                        index = count;
                        base.Seek(oldPos+count, SeekOrigin.Begin);
                        
                        testStream.Seek(oldPos, SeekOrigin.Begin);
                        var iiii = testStream.Read(lz4Cache, offset, count);
                        
                        Debug.LogFormat("Seeeeeeeeek: {0} {1} {2} {3}",Position, testStream.Position, index, iiii);
                        
                        // for (int i = 0; i < count; ++i)
                        // {
                        //     array[i] = lz4Cache[i];
                        // }
                        //
                        
                        for (int i = 0; i < count; ++i)
                        {
                            sm4[i] = array[i];
                        }
                        
                        tempBytes[oldPos] = sm4;
                        
                        
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