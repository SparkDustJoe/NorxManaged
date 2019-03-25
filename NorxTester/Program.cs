using System;
using System.Diagnostics;
using System.IO;

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
                    WriteThis("  CIPHERTEXT:     -PASS-", true, WType.Awesome);
                    if (expectedTag.CompareTo(resultTag) != 0)
                        WriteThis("  TAG:            *FAIL!*", true, WType.Error);
                    else
                    {
                        WriteThis("  TAG:            -PASS-", true, WType.Awesome);
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
                // MEMORY STREAM TESTS
                WriteThis("-- 32 TEST " + TESTCASENUM + " -- MS Disconnected Tag --", true, WType.Heading);
                using (MemoryStream outputMS = new MemoryStream(0))
                using (MemoryStream outputTAG = new MemoryStream(0))
                {
                    outcome = NorxManaged.Norx32.EncryptStream_Detached(
                        new MemoryStream(tcx32.Header),
                        new MemoryStream(tcx32.Payload),
                        new MemoryStream(tcx32.Trailer),
                        tcx32.Key, tcx32.Nonce,
                        tcx32.Rounds, tcx32.Parallelism,
                        tcx32.TagSizeBits,
                        outputMS, outputTAG);
                    expected = TestCases.BytesToHexString(tcx32.ResultingCT);
                    expectedTag = TestCases.BytesToHexString(tcx32.ResultingTag);
                    resultOutput = TestCases.BytesToHexString(outputMS.ToArray());
                    resultTag = TestCases.BytesToHexString(outputTAG.ToArray());
                    if (expected.CompareTo(resultOutput) != 0)
                    {
                        WriteThis("  MS CIPHERTEXT:  *FAIL!*", true, WType.Error);
                    }
                    else
                    {
                        WriteThis("  MS CIPHERTEXT:  -PASS-", true, WType.Awesome);
                        if (expectedTag.CompareTo(resultTag) != 0)
                        {
                            WriteThis("  MS TAG:         *FAIL!*", true, WType.Error);
                        }
                        else
                        {
                            WriteThis("  MS TAG:         -PASS-", true, WType.Awesome);
                            outputMS.Seek(0, SeekOrigin.Begin);
                            using (MemoryStream outputMS2 = new MemoryStream(0))
                            {
                                outcome = NorxManaged.Norx32.DecryptVerifyStream_Detached(
                                    new MemoryStream(tcx32.Header),
                                    outputMS,
                                    new MemoryStream(tcx32.Trailer),
                                    tcx32.Key, tcx32.Nonce,
                                    tcx32.Rounds, tcx32.Parallelism,
                                    outputTAG.ToArray(),
                                    outputMS2);
                                expected = TestCases.BytesToHexString(tcx32.Payload);
                                resultOutput = TestCases.BytesToHexString(outputMS2.ToArray());
                                if (outcome == -1)
                                    WriteThis("  MS TAG VERIFY:  *FAIL!*", true, WType.Error);
                                else
                                {
                                    WriteThis("  TAG VERIFY:     -PASS-", true, WType.Awesome);
                                    if (expected.CompareTo(resultOutput) != 0)
                                        WriteThis("  MS PLAINTEXT:   *FAIL!*", true, WType.Error);
                                    else
                                        WriteThis("  MS PLAINTEXT:   -PASS-", true, WType.Awesome);
                                }
                            }
                        }
                    }
                }
            }
            ////64BIT TYPE A==========================================================
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
                {
                    Debug.Print("*CIPHERTEXT FAIL:\r\n-EXPECTED:" + expected);
                    Debug.Print("-RESULT  :" + resultOutput);
                    WriteThis("  CIPHERTEXT:     *FAIL!*", true, WType.Error);
                }
                else
                {
                    WriteThis("  CIPHERTEXT:     -PASS-", true, WType.Awesome);
                    if (expectedTag.CompareTo(resultTag) != 0)
                        WriteThis("  TAG:            *FAIL!*", true, WType.Error);
                    else
                    {
                        WriteThis("  TAG:            -PASS-", true, WType.Awesome);
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
                // MEMORY STREAM TESTS
                WriteThis("-- 64 TEST " + TESTCASENUM + " -- MS Disconnected Tag --", true, WType.Heading);
                using (MemoryStream outputMS = new MemoryStream(0))
                using (MemoryStream outputTAG = new MemoryStream(0))
                {
                    outcome = NorxManaged.Norx64.EncryptStream_Detached(
                        new MemoryStream(tcx64.Header),
                        new MemoryStream(tcx64.Payload),
                        new MemoryStream(tcx64.Trailer),
                        tcx64.Key, tcx64.Nonce,
                        tcx64.Rounds, tcx64.Parallelism,
                        tcx64.TagSizeBits,
                        outputMS, outputTAG);
                    expected = TestCases.BytesToHexString(tcx64.ResultingCT);
                    expectedTag = TestCases.BytesToHexString(tcx64.ResultingTag);
                    resultOutput = TestCases.BytesToHexString(outputMS.ToArray());
                    resultTag = TestCases.BytesToHexString(outputTAG.ToArray());
                    if (expected.CompareTo(resultOutput) != 0)
                    {
                        Debug.Print("*CIPHERTEXT FAIL:\r\n-EXPECTED:" + expected);
                        Debug.Print("-RESULT  :" + resultOutput);
                        WriteThis("  MS CIPHERTEXT:  *FAIL!*", true, WType.Error);
                    }
                    else
                    {
                        WriteThis("  MS CIPHERTEXT:  -PASS-", true, WType.Awesome);
                        if (expectedTag.CompareTo(resultTag) != 0)
                        {
                            Debug.Print("*TAG FAIL:\r\n-EXPECTED:" + expectedTag);
                            Debug.Print("-RESULT  :" + resultTag);
                            WriteThis("  MS TAG:         *FAIL!*", true, WType.Error);
                        }
                        else
                        {
                            WriteThis("  MS TAG:         -PASS-", true, WType.Awesome);
                            outputMS.Seek(0, SeekOrigin.Begin);
                            using (MemoryStream outputMS2 = new MemoryStream(0))
                            {
                                outcome = NorxManaged.Norx64.DecryptVerifyStream_Detached(
                                    new MemoryStream(tcx64.Header),
                                    outputMS,
                                    new MemoryStream(tcx64.Trailer),
                                    tcx64.Key, tcx64.Nonce,
                                    tcx64.Rounds, tcx64.Parallelism,
                                    outputTAG.ToArray(),
                                    outputMS2);
                                expected = TestCases.BytesToHexString(tcx64.Payload);
                                resultOutput = TestCases.BytesToHexString(outputMS2.ToArray());
                                if (outcome == -1)
                                    WriteThis("  MS TAG VERIFY:  *FAIL!*", true, WType.Error);
                                else
                                {
                                    WriteThis("  MS TAG VERIFY:  -PASS-", true, WType.Awesome);
                                    if (expected.CompareTo(resultOutput) != 0)
                                        WriteThis("  MS PLAINTEXT:   *FAIL!*", true, WType.Error);
                                    else
                                        WriteThis("  MS PLAINTEXT:   -PASS-", true, WType.Awesome);
                                }
                            }
                        }
                    }
                }
            }
            // TYPE B=================================================================================
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
                // MEMORY STREAM TESTS
                WriteThis("-- 32 TEST " + TESTCASENUM + " -- MS Integral Tag", true, WType.Heading);
                using (MemoryStream outputMS = new MemoryStream(0))
                {
                    outcome = NorxManaged.Norx32.EncryptStream(
                        new MemoryStream(tcx32.Header),
                        new MemoryStream(tcx32.Payload),
                        new MemoryStream(tcx32.Trailer),
                        tcx32.Key, tcx32.Nonce,
                        tcx32.Rounds, tcx32.Parallelism,
                        tcx32.TagSizeBits,
                        outputMS);
                    expected = TestCases.BytesToHexString(tcx32.ResultingCT) + TestCases.BytesToHexString(tcx32.ResultingTag);
                    resultOutput = TestCases.BytesToHexString(outputMS.ToArray());
                    if (expected.CompareTo(resultOutput) != 0)
                        WriteThis("  MS CT/TAG:      *FAIL!*", true, WType.Error);
                    else
                    {
                        WriteThis("  MS CT/TAG:      -PASS-", true, WType.Awesome);
                        outputMS.Seek(0, SeekOrigin.Begin);
                        using (MemoryStream outputMS2 = new MemoryStream(0))
                        {
                            outcome = NorxManaged.Norx32.DecryptVerifyStream(
                                new MemoryStream(tcx32.Header),
                                outputMS,
                                new MemoryStream(tcx32.Trailer),
                                tcx32.Key, tcx32.Nonce,
                                tcx32.Rounds, tcx32.Parallelism,
                                tcx32.TagSizeBits,
                                outputMS2);
                            expected = TestCases.BytesToHexString(tcx32.Payload);
                            resultOutput = TestCases.BytesToHexString(outputMS2.ToArray());
                            if (outcome == -1)
                                WriteThis("  MS TAG VERIFY:  *FAIL!*", true, WType.Error);
                            else
                            {
                                WriteThis("  MS TAG VERIFY:  -PASS-", true, WType.Awesome);
                                if (expected.CompareTo(resultOutput) != 0)
                                    WriteThis("  MS PLAINTEXT:   *FAIL!*", true, WType.Error);
                                else
                                    WriteThis("  MS PLAINTEXT:   -PASS-", true, WType.Awesome);
                            }
                        }
                    }
                }
            }
            ////// 64 BIT TYPE B===============================================================================
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
                        {
                            Debug.Print("*PLAINTEXT  FAIL:\r\n-EXPECTED:" + expected);
                            Debug.Print("-RESULT  :" + resultOutput);
                            WriteThis("  PLAINTEXT:      *FAIL!*", true, WType.Error);
                        }
                        else
                            WriteThis("  PLAINTEXT:      -PASS-", true, WType.Awesome);
                    }
                }
                // MEMORY STREAM TESTS
                WriteThis("-- 64 TEST " + TESTCASENUM + " -- MS Integral Tag", true, WType.Heading);
                using (MemoryStream outputMS = new MemoryStream())
                {
                    outcome = NorxManaged.Norx64.EncryptStream(
                        new MemoryStream(tcx64.Header),
                        new MemoryStream(tcx64.Payload),
                        new MemoryStream(tcx64.Trailer),
                        tcx64.Key, tcx64.Nonce,
                        tcx64.Rounds, tcx64.Parallelism,
                        tcx64.TagSizeBits,
                        outputMS);
                    expected = TestCases.BytesToHexString(tcx64.ResultingCT) + TestCases.BytesToHexString(tcx64.ResultingTag);
                    resultOutput = TestCases.BytesToHexString(outputMS.ToArray());
                    if (expected.CompareTo(resultOutput) != 0)
                        WriteThis("  MS CT/TAG:      *FAIL!*", true, WType.Error);
                    else
                    {
                        WriteThis("  MS CT/TAG:      -PASS-", true, WType.Awesome);
                        outputMS.Seek(0, SeekOrigin.Begin);
                        using (MemoryStream outputMS2 = new MemoryStream())
                        {
                            outcome = NorxManaged.Norx64.DecryptVerifyStream(
                                new MemoryStream(tcx64.Header),
                                outputMS,
                                new MemoryStream(tcx64.Trailer),
                                tcx64.Key, tcx64.Nonce,
                                tcx64.Rounds, tcx64.Parallelism,
                                tcx64.TagSizeBits,
                                outputMS2);
                            expected = TestCases.BytesToHexString(tcx64.Payload);
                            resultOutput = TestCases.BytesToHexString(outputMS2.ToArray());
                            if (outcome == -1)
                                WriteThis("  MS TAG VERIFY:  *FAIL!*", true, WType.Error);
                            else
                            {
                                WriteThis("  MS TAG VERIFY:  -PASS-", true, WType.Awesome);
                                if (expected.CompareTo(resultOutput) != 0)
                                {
                                    Debug.Print("*PLAINTEXT  FAIL:\r\n-EXPECTED:" + expected);
                                    Debug.Print("-RESULT  :" + resultOutput);
                                    WriteThis("  MS PLAINTEXT:   *FAIL!*", true, WType.Error);
                                }
                                else
                                    WriteThis("  MS PLAINTEXT:   -PASS-", true, WType.Awesome);
                            }
                        }
                    }
                }
            }
            while (Console.KeyAvailable) Console.ReadKey(true);
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
            Debug.Print(message);
        }
    }
}
