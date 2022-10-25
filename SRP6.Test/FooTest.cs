using srp6test;
using System.Numerics;
using System.Text;

namespace SRP6.Test
{
    public class FooTest
    {
        private BigInteger _salt = new BigInteger(new byte[]
        {
            0xCA, 0xC9, 0x4A, 0xF3, 0x2D, 0x81, 0x7B, 0xA6,
            0x4B, 0x13, 0xF1, 0x8F, 0xDE, 0xDE, 0xF9, 0x2A,
            0xD4, 0xED, 0x7E, 0xF7, 0xAB, 0x0E, 0x19, 0xE9,
            0xF2, 0xAE, 0x13, 0xC8, 0x28, 0xAE, 0xAF, 0x57,
        }, false, true);

        [Theory]
        [InlineData("00XD0QOSA9L8KMXC", "43R4Z35TKBKFW8JI", "E2F9A0F1E824006C98DA753448E743F7DAA1EAA1")]
        public void CanCalculateProperXValuesTheory(string username, string password, string expectedX)
        {
            // Arrange
            var srp = new Foo();

            // Act
            var actualX = Foo.CalculateX(username, password, _salt);

            // Assert
            Assert.Equal(expectedX, ByteArrayToString(actualX.ToByteArray()).ToUpper());
        }

        [Theory]
        [InlineData("CAC94AF32D817BA64B13F18FDEDEF92AD4ED7EF7AB0E19E9F2AE13C828AEAF57", "D927E98BE3E9AF84FDC99DE9034F8E70ED7E90D6")]
        public void CanCalculateXValuesWithDifferentSaltsTheory(string salt, string expectedX)
        {
            // Arrange
            var saltBI = new BigInteger(StringToByteArray(salt), false, true);
            
            // Act
            var actualX = Foo.CalculateX("USERNAME123", "PASSWORD123", saltBI);

            // Assert
            Assert.Equal(expectedX, ByteArrayToString(actualX.ToByteArray()).ToUpper());

        }
        

        private static byte[] StringToByteArray(string hex)
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

        private static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
    }
}