using System;
using System.IO;
using Encrypt;
using TMPro;
using UnityEngine;
using UnityEngine.SceneManagement;

namespace Test
{
    public class SM4Test : MonoBehaviour
    {
        public TMP_Text assetName;
        public TMP_Text assetTypeName;

        private string _assetName;
        private string _assetPostfix;

        private string _assetPathName;
        private string _assetPath;
        private string _cryptoPath;
        private string _decryptoPath;
        private string _paddingPath;

        private string _cryptoPkcs7Path;
        private string _decryptoPkcs7Path;


        private bool isScene;
        
        private Sm4Stream  _sm4Stream;
        private FileStream _fileStream;
        
        private void Awake()
        {
            EncryptType();
        }
        
        private void OnDestroy()
        {
            _fileStream?.Close();
            _sm4Stream?.Close();
        }

        public void EncryptType()
        {
            isScene = !isScene;
            if (isScene)
            {
                _assetName         = TestDefine.sceneName_lz4;
                _assetPostfix      = TestDefine.scenePostfix;
                assetTypeName.text = "Scene";
            }
            else
            {
                _assetName         = TestDefine.dataName_lzma;
                _assetPostfix      = TestDefine.dataPostfix;
                assetTypeName.text = "Data";
            }

            RefreshPath();
        }

        private void RefreshPath()
        {
            assetName.text = _assetName;
            _assetPathName = String.Format("{0}/{1}", Application.streamingAssetsPath, _assetName);

            _assetPath    = String.Format("{0}.{1}",   _assetPathName, _assetPostfix);
            _cryptoPath   = String.Format("{0}_c.{1}", _assetPathName, _assetPostfix);
            _decryptoPath = String.Format("{0}_d.{1}", _assetPathName, _assetPostfix);
            _paddingPath  = String.Format("{0}_p.{1}", _assetPathName, _assetPostfix);

            _cryptoPkcs7Path   = String.Format("{0}_pkcs7_c.{1}", _assetPathName, _assetPostfix);
            _decryptoPkcs7Path = String.Format("{0}_pkcs7_d.{1}", _assetPathName, _assetPostfix);
        }

        public void PaddingRaw()
        {
            EncryptFile.PaddingRaw(_assetPath, _paddingPath);
            Debug.Log("OK");
        }

        public void CryptoNoPadding()
        {
            var begin = Time.realtimeSinceStartup;
            EncryptFile.SegmentCryptoNoPadding(_paddingPath, _cryptoPath, Sm4Define.segmentSize, true);
            Debug.LogFormat("OK:{0}", Time.realtimeSinceStartup - begin);
        }

        public void DecryptoNoPadding()
        {
            var begin = Time.realtimeSinceStartup;
            EncryptFile.SegmentCryptoNoPadding(_cryptoPath, _decryptoPath, Sm4Define.segmentSize, false);
            Debug.LogFormat("OK:{0}", Time.realtimeSinceStartup - begin);
        }

        public void CryptoPKCS7()
        {
            EncryptFile.SegmentCryptoPKCS7(_assetPath, _cryptoPkcs7Path, true);
            Debug.Log("OK");
        }

        public void DecryptoPKCS7()
        {
            EncryptFile.SegmentCryptoPKCS7(_cryptoPkcs7Path, _decryptoPkcs7Path, false);
            Debug.Log("OK");
        }
        
        public void LoadAssetBundle()
        {
            var begin = Time.realtimeSinceStartup;
            if (_sm4Stream == null)
                _sm4Stream = new Sm4Stream(_cryptoPath, FileMode.Open, FileAccess.Read, FileShare.None,
                    Sm4Define.segmentSize, false, Sm4Define.key);

            var myLoadedAssetBundle = AssetBundle.LoadFromStream(_sm4Stream, 0, Sm4Define.segmentSize);
            PrintAssetBundleInfo(myLoadedAssetBundle);
            Debug.LogFormat("OK:{0}", Time.realtimeSinceStartup - begin);
        }

        public void LoadFile()
        {
            var begin               = Time.realtimeSinceStartup;
            var myLoadedAssetBundle = AssetBundle.LoadFromFile(_assetPath);
            PrintAssetBundleInfo(myLoadedAssetBundle);
            Debug.LogFormat("OK:{0}", Time.realtimeSinceStartup - begin);
        }
        
        public void LoadLZ4AssetBundle()
        {
            var begin = Time.realtimeSinceStartup;
            var assetPath = String.Format("{0}/{1}_p.{2}", Application.streamingAssetsPath, TestDefine.sceneName_lz4,
                TestDefine.scenePostfix);

            if (_fileStream == null)
                _fileStream = new FileStream(assetPath, FileMode.Open);

            var myLoadedAssetBundle = AssetBundle.LoadFromStream(_fileStream);
            PrintAssetBundleInfo(myLoadedAssetBundle);
            Debug.LogFormat("OK:{0}", Time.realtimeSinceStartup - begin);
        }

        private static void PrintAssetBundleInfo(AssetBundle myLoadedAssetBundle)
        {
            var assetNames = myLoadedAssetBundle.GetAllAssetNames();
            if (assetNames.Length != 0)
            {
                foreach (var assetName in assetNames)
                {
                    Debug.LogFormat("===============Asset {0}", assetName);
                    var asset = myLoadedAssetBundle.LoadAsset(assetName);

                    Debug.LogFormat("==============={0} Context:{1}", asset.GetType(), asset);
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