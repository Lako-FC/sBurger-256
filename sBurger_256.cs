using System;
using System.Collections;

public class sBurger_256
{
    private readonly int[] B = new int[4];
    private readonly int[] F = new int[4];
    public byte[] key = new byte[32];

    public void GenerationSettings()
    {
        //Formula
        string sumbytes = Default_Tools.SumByte(key, 0, key.Length).ToString();
        int tmp_position_parameters = (Convert.ToInt32(sumbytes[sumbytes.Length - 1].ToString()) + Convert.ToInt32(sumbytes[sumbytes.Length - 2].ToString()));

        int[] bits = Default_Tools.ByteToBits(key[tmp_position_parameters]);
        int type = key[tmp_position_parameters] % 2 != 0 ? 0 : 1;

        for (int i = 0; i < B.Length; i++)
        {
            B[i] = Convert.ToInt32(sumbytes[i].ToString()) + Default_Tools.SummaSymbol(bits, type, (2 * i), 8 - (7 - (2 * i)));
        }
        for (int i = 1; i <= F.Length; i++)
        {
            F[i - 1] = Convert.ToInt32(Default_Tools.SumByte(key, (8 * i) - 8, 8 * i).ToString()[0].ToString());
        }
    }

    public byte[] Encryption(byte[] encrypt_data)
    {
        if (F[1] % 2 != 0) Array.Reverse(encrypt_data);
        for (int i = 0; i < encrypt_data.Length; i++)
        {
            if (B[2] % 2 == 0) encrypt_data[i] = Crypt_Tools.Xor(encrypt_data[i], (byte)B[2]);
            if (B[0] % 2 != 0) encrypt_data[i] = Crypt_Tools.InversionByte(encrypt_data[i]);

            if (F[0] % 8 != 0) encrypt_data[i] = Crypt_Tools.Offset_Left(encrypt_data[i], F[0] - (8 * (F[0] / 8)));
            encrypt_data[i] = Crypt_Tools.Xor(encrypt_data[i], key[i]);
            if (B[1] % 2 != 0) encrypt_data[i] = Crypt_Tools.InversionByte(encrypt_data[i]);

            if (F[2] % 8 != 0) encrypt_data[i] = Crypt_Tools.Offset_Right(encrypt_data[i], F[2] - (8 * (F[2] / 8)));
            if (B[3] % 2 == 0) encrypt_data[i] = Crypt_Tools.Xor(encrypt_data[i], (byte)B[3]);
        }
        if (F[3] % 2 != 0) Array.Reverse(encrypt_data);

        return encrypt_data;
    }
    public byte[] Decryption(byte[] decrypt_data)
    {
        if (F[3] % 2 != 0) Array.Reverse(decrypt_data);
        for (int i = 0; i < decrypt_data.Length; i++)
        {
            if (B[3] % 2 == 0) decrypt_data[i] = Crypt_Tools.Xor(decrypt_data[i], (byte)B[3]);
            if (F[2] % 8 != 0) decrypt_data[i] = Crypt_Tools.Offset_Left(decrypt_data[i], F[2] - (8 * (F[2] / 8)));

            if (B[1] % 2 != 0) decrypt_data[i] = Crypt_Tools.InversionByte(decrypt_data[i]);
            decrypt_data[i] = Crypt_Tools.Xor(decrypt_data[i], key[i]);
            if (F[0] % 8 != 0) decrypt_data[i] = Crypt_Tools.Offset_Right(decrypt_data[i], F[0] - (8 * (F[0] / 8)));

            if (B[0] % 2 != 0) decrypt_data[i] = Crypt_Tools.InversionByte(decrypt_data[i]);
            if (B[2] % 2 == 0) decrypt_data[i] = Crypt_Tools.Xor(decrypt_data[i], (byte)B[2]);
        }
        if (F[1] % 2 != 0) Array.Reverse(decrypt_data);

        return decrypt_data;
    }

    public class Default_Tools
    {
        public static int SummaSymbol(int[] bits, int type, int start, int stop)
        {
            int result = 0;

            for (int i = start; i <= stop; i++) if (bits[i] == type) result++; //0 or 1

            return result;
        }
        public static int SumByte(byte[] bytes, int start, int stop)
        {
            int result = 0;

            for (int i = start; i < stop; i++)
            {
                result += bytes[i];
            }

            return result;
        }
        public static int[] ByteToBits(byte bytes)
        {
            BitArray bitArray = new BitArray(new byte[] { bytes });
            int[] result = new int[8];

            for (int b = 1; b <= 8; b++) result[b - 1] = Convert.ToInt32(bitArray[bitArray.Length - b]);

            return result;
        }
        public static byte BitsToByte(int[] bits)
        {
            Array.Reverse(bits);
            byte result = 0;

            for (byte i = 0; i < bits.Length; i++)
            {
                if (bits[i] != 0) result |= (byte)(1 << i);
            }

            return result;
        }
    }
    public class Crypt_Tools
    {
        public static byte Offset_Left(byte _byte, int s = 1) => (byte)((_byte << s) | (_byte >> 8 - s));
        public static byte Offset_Right(byte _byte, int s = 1) => (byte)((_byte >> s) | (_byte << 8 - s));
        public static byte Xor(byte a, byte b) => (byte)(a ^ b);
        public static byte InversionByte(byte _byte) => (byte)(~_byte);
    }
}