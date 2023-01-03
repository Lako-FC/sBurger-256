/*
    Link: github.com/0xLaileb/sBurger-256
    Version: v0.2
*/

using System;
using System.Collections;

public class sBurger256
{
    public byte[] Key = new byte[32];
    
    private readonly int[] _b = new int[4];
    private readonly int[] _f = new int[4];

    public void GenerationSettings()
    {
        // Formula
        var sumbytes = DefaultTools.SumByte(Key, 0, Key.Length).ToString();
        var positionParameters = Convert.ToInt32(sumbytes[^1].ToString()) + Convert.ToInt32(sumbytes[^2].ToString());

        var bits = DefaultTools.ByteToBits(Key[positionParameters]);
        var type = Key[positionParameters] % 2 != 0 ? 0 : 1;

        for (var i = 0; i < _b.Length; i++)
        {
            _b[i] = Convert.ToInt32(sumbytes[i].ToString()) + DefaultTools.SummaSymbol(bits, type, 2 * i, 8 - (7 - 2 * i));
        }
        
        for (var i = 1; i <= _f.Length; i++)
        {
            _f[i - 1] = Convert.ToInt32(DefaultTools.SumByte(Key, 8 * i - 8, 8 * i).ToString()[0].ToString());
        }
    }

    public byte[] Encryption(byte[] encryptData)
    {
        if (_f[1] % 2 != 0) 
            Array.Reverse(encryptData);
        
        for (var i = 0; i < encryptData.Length; i++)
        {
            if (_b[2] % 2 == 0) encryptData[i] = CryptTools.Xor(encryptData[i], (byte)_b[2]);
            if (_b[0] % 2 != 0) encryptData[i] = CryptTools.InversionByte(encryptData[i]);

            if (_f[0] % 8 != 0) encryptData[i] = CryptTools.OffsetLeft(encryptData[i], _f[0] - 8 * (_f[0] / 8));
            encryptData[i] = CryptTools.Xor(encryptData[i], Key[i]);
            if (_b[1] % 2 != 0) encryptData[i] = CryptTools.InversionByte(encryptData[i]);

            if (_f[2] % 8 != 0) encryptData[i] = CryptTools.OffsetRight(encryptData[i], _f[2] - 8 * (_f[2] / 8));
            if (_b[3] % 2 == 0) encryptData[i] = CryptTools.Xor(encryptData[i], (byte)_b[3]);
        }
        
        if (_f[3] % 2 != 0) 
            Array.Reverse(encryptData);

        return encryptData;
    }
    
    public byte[] Decryption(byte[] decryptData)
    {
        if (_f[3] % 2 != 0) 
            Array.Reverse(decryptData);
        
        for (var i = 0; i < decryptData.Length; i++)
        {
            if (_b[3] % 2 == 0) decryptData[i] = CryptTools.Xor(decryptData[i], (byte)_b[3]);
            if (_f[2] % 8 != 0) decryptData[i] = CryptTools.OffsetLeft(decryptData[i], _f[2] - 8 * (_f[2] / 8));
            
            if (_b[1] % 2 != 0) decryptData[i] = CryptTools.InversionByte(decryptData[i]);
            decryptData[i] = CryptTools.Xor(decryptData[i], Key[i]);
            if (_f[0] % 8 != 0) decryptData[i] = CryptTools.OffsetRight(decryptData[i], _f[0] - 8 * (_f[0] / 8));
            
            if (_b[0] % 2 != 0) decryptData[i] = CryptTools.InversionByte(decryptData[i]);
            if (_b[2] % 2 == 0) decryptData[i] = CryptTools.Xor(decryptData[i], (byte)_b[2]);
        }
        
        if (_f[1] % 2 != 0) 
            Array.Reverse(decryptData);

        return decryptData;
    }

    private class DefaultTools
    {
        public static int SummaSymbol(IReadOnlyList<int> bits, int type, int start, int stop)
        {
            var result = 0;

            for (var i = start; i <= stop; i++)
            {
                if (bits[i] == type)
                {
                    result++; // 0 or 1
                }
            }

            return result;
        }
        
        public static int SumByte(IReadOnlyList<byte> bytes, int start, int stop)
        {
            var result = 0;

            for (var i = start; i < stop; i++)
            {
                result += bytes[i];
            }

            return result;
        }
        
        public static int[] ByteToBits(byte bytes)
        {
            var result = new int[8];
            
            var bitArray = new BitArray(new[] { bytes });

            for (var b = 1; b <= 8; b++)
            {
                result[b - 1] = Convert.ToInt32(bitArray[^b]);
            }

            return result;
        }
    }

    private class CryptTools
    {
        public static byte OffsetLeft(byte @byte, int s = 1) 
            => (byte)((@byte << s) | (@byte >> 8 - s));
        
        public static byte OffsetRight(byte @byte, int s = 1) 
            => (byte)((@byte >> s) | (@byte << 8 - s));
        
        public static byte Xor(byte a, byte b) 
            => (byte)(a ^ b);
        
        public static byte InversionByte(byte @byte) 
            => (byte)~@byte;
    }
}