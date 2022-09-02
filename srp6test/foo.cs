using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace srp6test;

/// <summary>
///
/// The SRP-6 algorithm is defined used mathematical letters,
/// the below table translates between short mathematical form and implementation name.
///
/// A => Client public key.
/// a => client private key.
/// 
/// B => Server public key.
/// b => server private key.
///
/// N => Large safe prime.
/// g => generator (always 7)
/// k => k value (always 3)
/// s => salt
/// U => username
/// p => password
/// v => password verifier
/// M1 => Client proof (proof first sent by client, calculated by both)
/// M2 => (proof first sent by server, calculated by both)
/// M => (Client OR Server) proof
/// S => S key (????)
/// K => Session key
/// </summary>
public class Foo
{

    /// <summary>
    /// Large safe prime represented as little endian.
    /// </summary>
    private static readonly BigInteger LARGE_SAFE_PRIME_LITTLE_ENDIAN = new(new byte[]
    {
        0xb7, 0x9b, 0x3e, 0x2a, 0x87, 0x82, 0x3c, 0xab,
        0x8f, 0x5e, 0xbf, 0xbf, 0x8e, 0xb1, 0x01, 0x08,
        0x53, 0x50, 0x06, 0x29, 0x8b, 0x5b, 0xad, 0xbd,
        0x5b, 0x53, 0xe1, 0x89, 0x5e, 0x64, 0x4b, 0x89
    });

    
    
    /// <summary>
    /// Large safe prime represented as big endian.
    /// </summary>
    private static readonly BigInteger LARGE_SAFE_PRIME_BIG_ENDIAN = new(new byte[]
    {
        0x89, 0x4b, 0x64, 0x5e, 0x89, 0xe1, 0x53, 0x5b,
        0xbd, 0xad, 0x5b, 0x8b, 0x29, 0x06, 0x50, 0x53,
        0x08, 0x01, 0xb1, 0x8e, 0xbf, 0xbf, 0x5e, 0x8f,
        0xab, 0x3c, 0x82, 0x87, 0x2a, 0x3e, 0x9b, 0xb7,
    });

    /// <summary>
    /// The generator should always be 7.
    /// </summary>
    private static readonly BigInteger GENERATOR_VALUE_ALWAYS_7 = new(7);

    /// <summary>
    /// The K value used in the algorithm should always be 3 (why? i don't know.)
    /// </summary>
    private static readonly BigInteger K_VALUE_ALWAYS_3 = new(3);


    /// <summary>
    /// Calculates the password verifier, v = g^x % N
    /// </summary>
    /// <param name="username">The username of the connecting client.</param>
    /// <param name="password">The password of the connecting client.</param>
    /// <param name="salt">Little Endian byte array of length 32.</param>
    /// <returns>Little Endian byte array of length 32.</returns>
    private static BigInteger CalculatePasswordVerifier(string username, string password, BigInteger salt)
    {
        // Calculate the X value, store as BigInteger.
        var x = CalculateX(username, password, salt);
        
        return BigInteger.ModPow(GENERATOR_VALUE_ALWAYS_7, x, LARGE_SAFE_PRIME_LITTLE_ENDIAN);

    }

    /// <summary>
    /// Calculates the x value which is necessary to calculate the password verifier.
    /// </summary>
    /// <param name="username"></param>
    /// <param name="password"></param>
    /// <param name="salt">Little Endian byte array of salt is expected.</param>
    /// <returns></returns>
    public static BigInteger CalculateX(string username, string password, BigInteger salt)
    {
        var U = username.ToUpper();
        var p = password.ToUpper();

        var innerToBeHashed = Encoding.ASCII.GetBytes(U + ":" + p);
        var innerHashed = SHA1.HashData(innerToBeHashed);

        var finalToBeHashed = salt.ToByteArray().Concat(innerHashed).ToArray();

        // Reverse the output so it is returned as little endianness.
        return new BigInteger(SHA1.HashData(finalToBeHashed).Reverse().ToArray());
    }

    /// <summary>
    /// Calculates the server public key.
    /// </summary>
    /// <param name="passwordVerifier">Little Endian: The password verifier.</param>
    /// <param name="serverPrivateKey">Little Endian: The server private key.</param>
    /// <returns>Server public key in little endianness.</returns>
    public static BigInteger CalculateServerPublicKey(BigInteger passwordVerifier, BigInteger serverPrivateKey)
    {

        var kv = K_VALUE_ALWAYS_3 * passwordVerifier;

        var gbN = BigInteger.ModPow(GENERATOR_VALUE_ALWAYS_7, serverPrivateKey, LARGE_SAFE_PRIME_BIG_ENDIAN);

        var B = (kv + gbN) % LARGE_SAFE_PRIME_BIG_ENDIAN;

        return B;
        
        /*var B = (
                    K_VALUE_ALWAYS_3 * passwordVerifier 
                    +
                    (BigInteger.ModPow(GENERATOR_VALUE_ALWAYS_7, serverPrivateKey, LARGE_SAFE_PRIME_LITTLE_ENDIAN))
                    )
                % LARGE_SAFE_PRIME_LITTLE_ENDIAN;

        return B;*/
        
        var interim = 
            BigInteger
                .Multiply(K_VALUE_ALWAYS_3, passwordVerifier)
            +
            BigInteger
                .ModPow(GENERATOR_VALUE_ALWAYS_7,serverPrivateKey, LARGE_SAFE_PRIME_LITTLE_ENDIAN)
            ;

        BigInteger.DivRem(interim, LARGE_SAFE_PRIME_LITTLE_ENDIAN, out var modulusResult);

        return modulusResult;
    }
    
    
    // https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/
    // https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/verification_values/calculate_x_values.txt
    // https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/verification_values/calculate_x_values.txt
    // https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/verification_values/calculate_x_salt_values.txt
    // https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/#world-packet-header-encryption
    // https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/#reconnecting
}