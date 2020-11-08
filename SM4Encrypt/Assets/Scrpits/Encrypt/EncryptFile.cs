using System;
using System.Collections.Generic;
using System.IO;
using SecretUtils;

namespace Encrypt
{
    public static class EncryptFile
    {
        /// <summary>
        /// 文件大小16byte对齐
        /// </summary>
        /// <param name="assetPath"></param>
        /// <param name="paddingPath"></param>
        public static void PaddingRaw(string assetPath, string paddingPath)
        {
            if (File.Exists(paddingPath))
            {
                File.Delete(paddingPath);
            }
        
            File.Copy(assetPath, paddingPath);
            FileStream writeSteam = new FileStream(paddingPath, FileMode.Open);

            var padding = 16 - writeSteam.Length % 16;
            if (padding != 0)
            {
                byte[] padByte = new byte[padding];
            
                writeSteam.Position = writeSteam.Length;
                writeSteam.Write(padByte, 0, padByte.Length);
            }
            writeSteam.Close();
        }


        /// <summary>
        /// 大文件分段加密
        /// </summary>
        /// <param name="readPath"></param>
        /// <param name="writePath"></param>
        /// <param name="segmentSize">分段大小</param>
        /// <param name="crypto"></param>
        public static void SegmentCryptoNoPadding(string readPath, string writePath, int segmentSize ,bool crypto)
        {
            if (File.Exists(writePath))
            {
                File.Delete(writePath);
            }

            FileStream writeSteam = new FileStream(writePath, FileMode.Create);

            FileStream readStream = new FileStream(readPath, FileMode.Open);
            var        fileLength = readStream.Length;

            long   offset       = 0;
            var segmentBytes = new byte[segmentSize];
            
            while (offset < fileLength)
            {
                readStream.Seek(offset, SeekOrigin.Begin);

                long   tempSize = segmentSize;
                if (offset + segmentSize > fileLength)
                {
                    tempSize = fileLength - offset;
                    segmentBytes  = new byte[tempSize];
                }
                
                var tempLength = readStream.Read(segmentBytes, 0, (int)tempSize);
                
                if (tempLength <= 0)
                {
                    throw new EncryptException();
                }
                
                byte[] sm4;
                if (crypto)
                {
                    sm4 = Sm4Base.EncryptCBCNoPadding(segmentBytes, Sm4Define.key);
                }
                else
                {
                    sm4 = Sm4Base.DecryptCBCNoPadding(segmentBytes, Sm4Define.key);
                }
                
                writeSteam.Position = writeSteam.Length;
                writeSteam.Write(sm4, 0, sm4.Length);

                offset += tempLength;
                
                if (offset >= fileLength)
                {
                    break;
                }
            }

            readStream.Close();
            writeSteam.Close();
        }

        /// <summary>
        /// 大文件分段加密
        /// </summary>
        /// <param name="readPath"></param>
        /// <param name="writePath"></param>
        /// <param name="crypto"></param>
        public static void SegmentCryptoPKCS7(string readPath, string writePath, bool crypto)
        {
            if (File.Exists(writePath))
            {
                File.Delete(writePath);
            }

            FileStream writeSteam = new FileStream(writePath, FileMode.Create);

            FileStream readStream = new FileStream(readPath, FileMode.Open);
            var        fileLength = readStream.Length;

            long   offset = 0;
            byte[] fileByte;
            if (crypto)
            {
                fileByte = new byte[Sm4Define.segmentSizeSub1];
            }
            else
            {
                fileByte = new byte[Sm4Define.segmentSize];    
            }

            List<double> ticks = new List<double>();

            long   size  =0;
            long   size1 = 0;
            double t1;
            int    index = 0;
            while (offset < fileLength)
            {
                t1 = DateTime.Now.Ticks;

                readStream.Seek(offset, SeekOrigin.Begin);

                int    tempLength = -1;
                byte[] sm4;
                if (crypto)
                {
                    long tempCount = Sm4Define.segmentSizeSub1;
                    if (offset + Sm4Define.segmentSizeSub1 > fileLength)
                    {
                        tempCount = fileLength - offset;
                        fileByte  = new byte[fileLength - offset];
                    }
                
                    tempLength = readStream.Read(fileByte, 0, (int)tempCount);


                    if (tempLength <= 0)
                    {
                        //Debug.LogError(tempLength);
                        break;
                    }
                    size += tempLength;
                    sm4  =  Sm4Base.EncryptCBC(fileByte, Sm4Define.key);
                    
                }
                else
                {
                    long tempCount = Sm4Define.segmentSize;
                    if (offset + Sm4Define.segmentSize > fileLength)
                    {
                        tempCount = fileLength - offset;
                        fileByte  = new byte[fileLength - offset];
                    }
                
                    tempLength = readStream.Read(fileByte, 0, (int)tempCount);
                
                
                    if (tempLength <= 0)
                    {
                        //Debug.LogError(tempLength);
                        break;
                    }
                    size += tempLength;
                    sm4  =  Sm4Base.DecryptCBC(fileByte, Sm4Define.key);
                    
                }

                size1 += sm4.Length;
            
                writeSteam.Position = writeSteam.Length;
                writeSteam.Write(sm4, 0, sm4.Length);
                ticks.Add(DateTime.Now.Ticks - t1);

                offset += tempLength;
                ++index;
                if (offset >= fileLength)
                {
                    
                    break;
                }
            }

            readStream.Close();
            writeSteam.Close();
        }
    }
}
