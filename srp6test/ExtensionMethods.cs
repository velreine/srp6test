using System.Globalization;
using System.Numerics;

namespace srp6test;

public static class ExtensionMethods
{
    public static BigInteger ToBigInt(this string hex)
    {
        return BigInteger.Parse("0" + hex, NumberStyles.HexNumber);
    }

    public static BigInteger ToBigInt(this byte[] bytes)
    {
        return new BigInteger(bytes, true, true);
    }
    
}