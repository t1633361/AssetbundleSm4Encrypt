using System;
using System.IO;
using Encrypt;
using UnityEngine;
using UnityEngine.SceneManagement;

namespace Test
{
    public class SM4Test : MonoBehaviour
    {
        public static string dataName  = "1_lzma";
        public static string sceneName = "test_lzma";

        private static string _dataPostfix  = "data";
        private static string _scenePostfix = "scene";

        private static string _assetName    = sceneName;
        private static string _assetPostfix = _scenePostfix;
        private static string assetPathName = String.Format("{0}/{1}", Application.streamingAssetsPath, _assetName);

        private static string _assetPath    = String.Format("{0}.{1}",   assetPathName, _assetPostfix);
        private        string _cryptoPath   = String.Format("{0}_c.{1}", assetPathName, _assetPostfix);
        private        string _decryptoPath = String.Format("{0}_d.{1}", assetPathName, _assetPostfix);
        private        string _paddingPath  = String.Format("{0}_p.{1}", assetPathName, _assetPostfix);

        private string _cryptoPathPkcs7Path = String.Format("{0}_c.{1}",     assetPathName, _assetPostfix);
        private string _decryptoPkcs7Path   = String.Format("{0}_pkcs7.{1}", assetPathName, _assetPostfix);


        private bool isScene = true;

        private void Awake()
        {
            isScene = true;
        }

        public void EncryptType()
        {
            isScene = !isScene;
        }

        public void PaddingRaw()
        {
            EncryptFile.PaddingRaw(_assetPath, _paddingPath);
            Debug.Log("OK");
        }
        
        public void CryptoNoPadding()
        {
            EncryptFile.SegmentCryptoNoPadding(_paddingPath, _cryptoPath, Sm4Define.segmentSize,true);
            Debug.Log("OK");
        }

        public void DecryptoNoPadding()
        {
            EncryptFile.SegmentCryptoNoPadding(_cryptoPath, _decryptoPath, Sm4Define.segmentSize, false);
            Debug.Log("OK");
        }

        public void CryptoPKCS7()
        {
            EncryptFile.SegmentCryptoPKCS7(_paddingPath, _cryptoPath, true);
            Debug.Log("OK");
        }

        public void DecryptoPKCS7()
        {
            EncryptFile.SegmentCryptoPKCS7(_cryptoPath, _decryptoPath, false);
            Debug.Log("OK");
        }
        
        public void LoadAssetBundle()
        {
            LoadSm4AssetBundle(_cryptoPath);
        }

        private static void LoadSm4AssetBundle(string assetPath)
        {
            using (var fileStream = new Sm4Stream(assetPath, FileMode.Open))
            {
                var myLoadedAssetBundle = AssetBundle.LoadFromStream(fileStream);
                var assetNames          = myLoadedAssetBundle.GetAllAssetNames();
                if (assetNames.Length != 0)
                {
                    foreach (var assetName in assetNames)
                    {
                        Debug.LogFormat("===============Asset {0}", assetName);
                        var asset = myLoadedAssetBundle.LoadAsset(assetName);

                        Debug.LogFormat("==============={0}", asset.GetType());
                    }
                }
                else
                {
                    var sceneNames = myLoadedAssetBundle.GetAllScenePaths();
                    foreach (var sceneName in sceneNames)
                    {
                        Debug.LogFormat("===============Scene {0}", sceneName);
                    
                        SceneManager.LoadScene(sceneName, LoadSceneMode.Additive);
                    }
                }
            }
        }
    }
}