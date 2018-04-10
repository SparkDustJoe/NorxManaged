using System;

namespace NorxManaged.Tester
{
    class Program
    {
        static void Main(string[] args)
        {
            NorxManaged.TestCases tc = new TestCases();
            WriteThis("### Type A Tests = Disconnected Tag ### Type B Tests = Tag Integral with Ciphertext ###", true, WType.Info);
            // TYPE A
            WriteThis("== Tests Type A ==================================== ", true, WType.Heading);
            for (int TESTCASENUM = 0; TESTCASENUM < tc.Cases32.Length; TESTCASENUM++)
            {
                WriteThis("-- 32 TEST " + TESTCASENUM + " -- Disconnected Tag --", true, WType.Heading);
                TestCases.TestCase tcx32 = tc.Cases32[TESTCASENUM];
                byte[] output = null;
                byte[] output2 = null;
                byte[] tag = null;
                int outcome = NorxManaged.Norx32.Encrypt_Detached(
                    tcx32.Header,
                    tcx32.Payload,
                    tcx32.Trailer,
                    tcx32.Key, tcx32.Nonce,
                    tcx32.Rounds, tcx32.Parallelism,
                    tcx32.TagSizeBits,
                    out output,
                    out tag);
                string expected = TestCases.BytesToHexString(tcx32.ResultingCT);
                string expectedTag = TestCases.BytesToHexString(tcx32.ResultingTag);
                string resultOutput = TestCases.BytesToHexString(output);
                string resultTag = TestCases.BytesToHexString(tag);
                if (expected.CompareTo(resultOutput) != 0)
                    WriteThis("  CIPHERTEXT:     *FAIL!*", true, WType.Error);
                else
                {
                    if (expectedTag.CompareTo(resultTag) != 0)
                        WriteThis("  TAG:            *FAIL!*", true, WType.Error);
                    else
                    {
                        WriteThis("  TAG:            -PASS-", true, WType.Awesome);
                        WriteThis("  CIPHERTEXT:     -PASS-", true, WType.Awesome);
                        outcome = NorxManaged.Norx32.DecryptVerify_Detached(
                            tcx32.Header,
                            output,
                            tcx32.Trailer,
                            tcx32.Key, tcx32.Nonce,
                            tcx32.Rounds, tcx32.Parallelism,
                            tag,
                            out output2);
                        expected = TestCases.BytesToHexString(tcx32.Payload);
                        resultOutput = TestCases.BytesToHexString(output2);
                        if (outcome == -1)
                            WriteThis("  TAG VERIFY:     *FAIL!*", true, WType.Error);
                        else
                        {
                            WriteThis("  TAG VERIFY:     -PASS-", true, WType.Awesome);
                            if (expected.CompareTo(resultOutput) != 0)
                                WriteThis("  PLAINTEXT:      *FAIL!*", true, WType.Error);
                            else
                                WriteThis("  PLAINTEXT:      -PASS-", true, WType.Awesome);
                        }
                    }
                }
            }
            for (int TESTCASENUM = 0; TESTCASENUM < tc.Cases64.Length; TESTCASENUM++)
            {
                WriteThis("-- 64 TEST " + TESTCASENUM + " -- Disconnected Tag", true, WType.Heading);
                TestCases.TestCase tcx64 = tc.Cases64[TESTCASENUM];
                byte[] output = null;
                byte[] output2 = null;
                byte[] tag = null;
                int outcome = NorxManaged.Norx64.Encrypt_Detached(
                    tcx64.Header,
                    tcx64.Payload,
                    tcx64.Trailer,
                    tcx64.Key, tcx64.Nonce,
                    tcx64.Rounds, tcx64.Parallelism,
                    tcx64.TagSizeBits,
                    out output,
                    out tag);
                string expected = TestCases.BytesToHexString(tcx64.ResultingCT);
                string expectedTag = TestCases.BytesToHexString(tcx64.ResultingTag);
                string resultOutput = TestCases.BytesToHexString(output);
                string resultTag = TestCases.BytesToHexString(tag);
                if (expected.CompareTo(resultOutput) != 0)
                    WriteThis("  CIPHERTEXT:     *FAIL!*", true, WType.Error);
                else
                {
                    if (expectedTag.CompareTo(resultTag) != 0)
                        WriteThis("  TAG:            *FAIL!*", true, WType.Error);
                    else
                    {
                        WriteThis("  TAG:            -PASS-", true, WType.Awesome);
                        WriteThis("  CIPHERTEXT:     -PASS-", true, WType.Awesome);
                        outcome = NorxManaged.Norx64.DecryptVerify_Detached(
                        tcx64.Header,
                        output,
                        tcx64.Trailer,
                        tcx64.Key, tcx64.Nonce,
                        tcx64.Rounds, tcx64.Parallelism,
                        tag,
                        out output2);

                        expected = TestCases.BytesToHexString(tcx64.Payload);
                        resultOutput = TestCases.BytesToHexString(output2);
                        if (outcome == -1)
                            WriteThis("  TAG VERIFY:     *FAIL!*", true, WType.Error);
                        else
                        {
                            WriteThis("  TAG VERIFY:     -PASS-", true, WType.Awesome);
                            if (expected.CompareTo(resultOutput) != 0)
                                WriteThis("  PLAINTEXT:      *FAIL!*", true, WType.Error);
                            else
                                WriteThis("  PLAINTEXT:      -PASS-", true, WType.Awesome);
                        }
                    }
                }
            }
            // TYPE B
            WriteThis("== Tests Type B ==================================== ", true, WType.Heading);
            for (int TESTCASENUM = 0; TESTCASENUM < tc.Cases32.Length; TESTCASENUM++)
            {
                WriteThis("-- 32 TEST " + TESTCASENUM + " -- Integral Tag", true, WType.Heading);
                TestCases.TestCase tcx32 = tc.Cases32[TESTCASENUM];
                byte[] output = null;
                byte[] output2 = null;
                int outcome = NorxManaged.Norx32.Encrypt(
                    tcx32.Header,
                    tcx32.Payload,
                    tcx32.Trailer,
                    tcx32.Key, tcx32.Nonce,
                    tcx32.Rounds, tcx32.Parallelism,
                    tcx32.TagSizeBits,
                    out output);
                string expected = TestCases.BytesToHexString(tcx32.ResultingCT) + TestCases.BytesToHexString(tcx32.ResultingTag);
                string resultOutput = TestCases.BytesToHexString(output);
                if (expected.CompareTo(resultOutput) != 0)
                    WriteThis("  CIPHERTEXT/TAG: *FAIL!*", true, WType.Error);
                else
                {
                    WriteThis("  CIPHERTEXT/TAG: -PASS-", true, WType.Awesome);
                    outcome = NorxManaged.Norx32.DecryptVerify(
                        tcx32.Header,
                        output,
                        tcx32.Trailer,
                        tcx32.Key, tcx32.Nonce,
                        tcx32.Rounds, tcx32.Parallelism,
                        tcx32.TagSizeBits,
                        out output2);
                    expected = TestCases.BytesToHexString(tcx32.Payload);
                    resultOutput = TestCases.BytesToHexString(output2);
                    //if (outcome == -1)
                    //    WriteThis("  TAG VERIFY:     *FAIL!*", true, WType.Error);
                    //else
                    {
                        //WriteThis("  TAG VERIFY:     -PASS-", true, WType.Awesome);
                        if (expected.CompareTo(resultOutput) != 0)
                            WriteThis("  PLAINTEXT:      *FAIL!*", true, WType.Error);
                        else
                            WriteThis("  PLAINTEXT:      -PASS-", true, WType.Awesome);
                    }
                }
            }
            for (int TESTCASENUM = 0; TESTCASENUM < tc.Cases64.Length; TESTCASENUM++)
            {
                WriteThis("-- 64 TEST " + TESTCASENUM + " -- Integral Tag", true, WType.Heading);
                TestCases.TestCase tcx64 = tc.Cases64[TESTCASENUM];
                byte[] output = null;
                byte[] output2 = null;
                int outcome = NorxManaged.Norx64.Encrypt(
                    tcx64.Header,
                    tcx64.Payload,
                    tcx64.Trailer,
                    tcx64.Key, tcx64.Nonce,
                    tcx64.Rounds, tcx64.Parallelism,
                    tcx64.TagSizeBits,
                    out output);
                string expected = TestCases.BytesToHexString(tcx64.ResultingCT) + TestCases.BytesToHexString(tcx64.ResultingTag);
                string resultOutput = TestCases.BytesToHexString(output);
                if (expected.CompareTo(resultOutput) != 0)
                    WriteThis("  CIPHERTEXT/TAG: *FAIL!*", true, WType.Error);
                else
                {
                    WriteThis("  CIPHERTEXT/TAG: -PASS-", true, WType.Awesome);
                    outcome = NorxManaged.Norx64.DecryptVerify(
                        tcx64.Header,
                        output,
                        tcx64.Trailer,
                        tcx64.Key, tcx64.Nonce,
                        tcx64.Rounds, tcx64.Parallelism,
                        tcx64.TagSizeBits,
                        out output2);

                    expected = TestCases.BytesToHexString(tcx64.Payload);
                    resultOutput = TestCases.BytesToHexString(output2);
                    if (outcome == -1)
                        WriteThis("  TAG VERIFY:     *FAIL!*", true, WType.Error);
                    else
                    {
                        WriteThis("  TAG VERIFY:     -PASS-", true, WType.Awesome);
                        if (expected.CompareTo(resultOutput) != 0)
                            WriteThis("  PLAINTEXT:      *FAIL!*", true, WType.Error);
                        else
                            WriteThis("  PLAINTEXT:      -PASS-", true, WType.Awesome);
                    }
                }
            }
            Console.WriteLine("Press ENTER to exit...");
            Console.ReadLine();
        }

        public enum WType : byte
        {
            Normal = 0,
            Error = 1,
            Info = 2,
            Awesome = 4,
            Heading = 8
        }

        static void WriteThis(string message, bool crlf = true, WType type = WType.Normal)
        {
            ConsoleColor temp = Console.ForegroundColor;

            switch (type)
            {
                case WType.Error: Console.ForegroundColor = ConsoleColor.Red; break;
                case WType.Awesome: Console.ForegroundColor = ConsoleColor.Green; break;
                case WType.Heading: Console.ForegroundColor = ConsoleColor.Cyan; break;
                case WType.Info: Console.ForegroundColor = ConsoleColor.Yellow; break;
                case WType.Normal:
                default:
                    Console.ForegroundColor = ConsoleColor.Gray; break;
            }
            Console.Write(message);
            if (crlf) Console.WriteLine();
            Console.ForegroundColor = temp;
        }
    }
}
