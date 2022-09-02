// See https://aka.ms/new-console-template for more information

using System.Numerics;
using System.Text;
using srp6test;

Console.WriteLine("Hello, World!");



var salt = new BigInteger(new byte[]
{
    0xCA,0xC9,0x4A,0xF3,0x2D,0x81,0x7B,0xA6,
    0x4B,0x13,0xF1,0x8F,0xDE,0xDE,0xF9,0x2A,
    0xD4,0xED,0x7E,0xF7,0xAB,0x0E,0x19,0xE9,
    0xF2,0xAE,0x13,0xC8,0x28,0xAE,0xAF,0x57,
}, false, true);

var username = "USERNAME123";
var password = "PASSWORD123";


Console.WriteLine("Salt value is: " + salt);
var calculatedX = Foo.CalculateX(username, password, salt);

// Dummy password verifier.
var verifierString = "870A98A3DA8CCAFE6B2F4B0C43A022A0C6CEF4374BA4A50CEBF3FACA60237DC4";
var vBA = StringToByteArray(verifierString);
var v = new BigInteger(vBA, true, true);
Console.WriteLine("The value of v is: " + v);

var serverPrivateKeyString = "ACDCB7CB1DE67DB1D5E0A37DAE80068BCCE062AE0EDA0CBEADF560BCDAE6D6B9";
var serverPrivateKeyBA = StringToByteArray(serverPrivateKeyString);
var serverPrivateKey = new BigInteger(serverPrivateKeyBA, true, true);
Console.WriteLine("The value of server private key is: " + serverPrivateKey);

// Expected => 85A204C987B68764FA69C523E32B940D1E1822B9E0F134FDC5086B1408A2BB43

// TODO: stuck on calculating the server public key.
var serverPublicKey = Foo.CalculateServerPublicKey(v, serverPrivateKey);

Console.WriteLine("Server public key (original) is: " + ByteArrayToString(serverPublicKey.ToByteArray()));
Console.WriteLine("Server public key (reversed) is: " + ByteArrayToString(serverPublicKey.ToByteArray().Reverse().ToArray()));



static string ByteArrayToString(byte[] ba)
{
    StringBuilder hex = new StringBuilder(ba.Length * 2);
    foreach (byte b in ba)
        hex.AppendFormat("{0:x2}", b);
    return hex.ToString();
}

static byte[] StringToByteArray(string hex)
{
    if (hex.StartsWith("0x"))
    {
        hex = hex.Replace("0x", "");
    }
    
    return Enumerable.Range(0, hex.Length)
        .Where(x => x % 2 == 0)
        .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
        .ToArray();
}

Console.WriteLine("Value of X is: " + ByteArrayToString(calculatedX.ToByteArray()));

// TODO verify server public key:: https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/verification_values/calculate_B_values.txt