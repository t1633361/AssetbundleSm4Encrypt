using System;
using System.IO;
using Test;
using UnityEngine;

public class TestStream : FileStream
{
    private readonly string     sm4key;
    private          FileStream testStream;
    public TestStream(string path, FileMode mode, FileAccess access, FileShare share, int bufferSize, bool useAsync) 
        : base(path, mode, access, share, bufferSize, useAsync)
    {
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;

    public TestStream(string path, FileMode mode) : base(path, mode)
    {
        var assetPath = String.Format("{0}/{1}_p1.{2}", Application.streamingAssetsPath, TestDefine.sceneName_lz4,
            TestDefine.scenePostfix);
            
        testStream = new FileStream(assetPath, FileMode.Open);
    }

    public override int Read(byte[] array, int offset, int count)
    {
        testStream.Seek(Position, SeekOrigin.Begin);
        int index = base.Read(array, offset, count);
        index = testStream.Read(array, offset, count);
        Debug.LogFormat("Read:{0} {1} {2} {3}", testStream.Position, Position, count, index);
        return index;
    }
}