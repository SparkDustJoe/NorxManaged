using System;

namespace NorxManaged.Tester
{
    class Program
    {
        static void Main(string[] args)
        {
            NorxManaged.TestCases tc = new TestCases();
            for (int TESTCASENUM = 0; TESTCASENUM < 2; TESTCASENUM++)
            {
                byte[] tag = new byte[tc.Cases32[TESTCASENUM].TagSizeBits / 8];

                byte[] output = NorxManaged.Norx32.EncryptWithTag(
                    tc.Cases32[TESTCASENUM].Header,
                    tc.Cases32[TESTCASENUM].Payload,
                    tc.Cases32[TESTCASENUM].Trailer,
                    tc.Cases32[TESTCASENUM].Key, tc.Cases32[TESTCASENUM].Nonce,
                    tc.Cases32[TESTCASENUM].Rounds, tc.Cases32[TESTCASENUM].Parallelism,
                    tc.Cases32[TESTCASENUM].TagSizeBits, out tag);
                byte[] returnTrip = NorxManaged.Norx32.DecryptAndVerifyTag(
                    tc.Cases32[TESTCASENUM].Header,
                    output,
                    tc.Cases32[TESTCASENUM].Trailer,
                    tc.Cases32[TESTCASENUM].Key, tc.Cases32[TESTCASENUM].Nonce,
                    tc.Cases32[TESTCASENUM].Rounds, tc.Cases32[TESTCASENUM].Parallelism,
                    tag);
                if (CompareArrays(output, tc.Cases32[TESTCASENUM].ResultingCT) == false)
                    Console.WriteLine("32 TEST " + TESTCASENUM + ", CIPHERTEXT:     *FAIL!*");
                else
                    Console.WriteLine("32 TEST " + TESTCASENUM + ", CIPHERTEXT:     -PASS-");

                if (CompareArrays(returnTrip, tc.Cases32[TESTCASENUM].Payload) == false)
                    Console.WriteLine("32 TEST " + TESTCASENUM + ", RETURN TRIP:    *FAIL!*");
                else
                    Console.WriteLine("32 TEST " + TESTCASENUM + ", RETURN TRIP:    -PASS-");

                if (CompareArrays(tag, tc.Cases32[TESTCASENUM].ResultingTag) == false)
                    Console.WriteLine("32 TEST " + TESTCASENUM + ", TAG:            *FAIL!*");
                else
                    Console.WriteLine("32 TEST " + TESTCASENUM + ", TAG:            -PASS-");
            }
            for (int TESTCASENUM = 0; TESTCASENUM < 3; TESTCASENUM++)
            {
                byte[] tag = new byte[tc.Cases64[TESTCASENUM].TagSizeBits / 8];

                byte[] output = NorxManaged.Norx64.EncryptWithTag(
                    tc.Cases64[TESTCASENUM].Header,
                    tc.Cases64[TESTCASENUM].Payload,
                    tc.Cases64[TESTCASENUM].Trailer,
                    tc.Cases64[TESTCASENUM].Key, tc.Cases64[TESTCASENUM].Nonce,
                    tc.Cases64[TESTCASENUM].Rounds, tc.Cases64[TESTCASENUM].Parallelism,
                    tc.Cases64[TESTCASENUM].TagSizeBits, out tag);
                byte[] returnTrip = NorxManaged.Norx64.DecryptAndVerifyTag(
                    tc.Cases64[TESTCASENUM].Header,
                    output,
                    tc.Cases64[TESTCASENUM].Trailer,
                    tc.Cases64[TESTCASENUM].Key, tc.Cases64[TESTCASENUM].Nonce,
                    tc.Cases64[TESTCASENUM].Rounds, tc.Cases64[TESTCASENUM].Parallelism,
                    tag);
                if (CompareArrays(output, tc.Cases64[TESTCASENUM].ResultingCT) == false)
                    Console.WriteLine("64 TEST " + TESTCASENUM + ", CIPHERTEXT:     *FAIL!*");
                else
                    Console.WriteLine("64 TEST " + TESTCASENUM + ", CIPHERTEXT:     -PASS-");

                if (CompareArrays(returnTrip, tc.Cases64[TESTCASENUM].Payload) == false)
                    Console.WriteLine("64 TEST " + TESTCASENUM + ", RETURN TRIP:    *FAIL!*");
                else
                    Console.WriteLine("64 TEST " + TESTCASENUM + ", RETURN TRIP:    -PASS-");

                if (CompareArrays(tag, tc.Cases64[TESTCASENUM].ResultingTag) == false)
                    Console.WriteLine("64 TEST " + TESTCASENUM + ", TAG:            *FAIL!*");
                else
                    Console.WriteLine("64 TEST " + TESTCASENUM + ", TAG:            -PASS-");
            }
            Console.ReadKey(true);
        }

        static bool CompareArrays(byte[] a, byte[] b)
        {
            if (a == null || b == null)
                return false;
            //System.Diagnostics.Debug.Print(BitConverter.ToString(a));
            //System.Diagnostics.Debug.Print(BitConverter.ToString(b));
            return BitConverter.ToString(a).CompareTo(BitConverter.ToString(b)) == 0;
        }
    }
}
