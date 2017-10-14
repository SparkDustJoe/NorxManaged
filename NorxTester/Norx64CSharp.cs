using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace NorxManaged
{
    public class Norx64CS
    {
        // EQUIVELANT TO C++ UNION, ALLOWS POINTER-LIKE REFERENCE TO INTERNAL BYTES WITHOUT "UNSAFE" CODE
        [StructLayout(LayoutKind.Explicit)]
        internal struct UInt64ArrayAsBytes
        {
            [FieldOffset(0)]
            public byte[] bytes;
            [FieldOffset(0)]
            public UInt64[] uint64;

            public UInt64ArrayAsBytes(int uintCount)
            {
                bytes = new byte[uintCount * sizeof(UInt64)]; // required to prevent "uninitialed/unassigned" variable errors
                uint64 = new UInt64[uintCount];
            }

            public UInt64ArrayAsBytes(byte[] data)
            {
                if (data.Length % sizeof(UInt64) != 0)
                    throw new InvalidCastException("Data length must be an even multiple of " + sizeof(UInt64) + " bytes.");
                uint64 = new UInt64[data.Length / sizeof(UInt64)]; // required to prevent "uninitialed/unassigned" variable errors
                bytes = (byte[])data.Clone();
            }

            public UInt64ArrayAsBytes(UInt64[] data)
            {
                bytes = new byte[data.Length * sizeof(UInt64)]; // required to prevent "uninitialed/unassigned" variable errors
                uint64 = data;

            }
        }

        internal static readonly UInt64[] INIT_CONST = new UInt64[] { // from the standard, these constants are u8 through u15.  These can be calculated by processing F(new UInt64[]{0,1,2,3...15},2);
                                                            0xB15E641748DE5E6BUL, 0xAA95E955E10F8410UL, 0x28D1034441A9DD40UL, 0x7F31BBF964E93BF5UL,
                                                            0xB5E9E22493DFFB96UL, 0xB980C852479FAFBDUL, 0xDA24516BF55EAFD4UL, 0x86026AE8536F1501UL};
        private const int NORX_WordSize = 64;                               // Word width in BITS
        private const int NORX_NonceSize = (NORX_WordSize * 4);             // Nonce size
        private const int NORX_KeySize = (NORX_WordSize * 4);               // Key size
        private const int NORX_BSize = (NORX_WordSize * 16);                // Permutation/State width
        private const int NORX_CapacitySize = (NORX_WordSize * 4);          // Capacity/Tag size in BITS
        private const int NORX_CapacitySizeBytes = NORX_CapacitySize / 8;   // Capacity/Tag size in BYTES
        private const int NORX_RateSize = (NORX_BSize - NORX_CapacitySize); // Rate size in BITS
        private const int NORX_RateSizeBytes = NORX_RateSize / 8;           // Rate size in BYTES

        #region CORE FUNCTIONS
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static UInt64 RotateRight(UInt64 x, byte count)
        {
            return (x >> count) | (x << (64 - count));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static UInt64 _H(UInt64 x, UInt64 y)
        { return x ^ y ^ ((x & y) << 1); }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void _G(ref UInt64 aa, ref UInt64 bb, ref UInt64 cc, ref UInt64 dd)
        {
            aa = _H(aa, bb); dd = RotateRight(aa ^ dd, 8);
            cc = _H(cc, dd); bb = RotateRight(bb ^ cc, 19);
            aa = _H(aa, bb); dd = RotateRight(aa ^ dd, 40);
            cc = _H(cc, dd); bb = RotateRight(bb ^ cc, 63);
        }

        internal static void _F(ref UInt64[] state, int rounds)
        {
            for (int i = 0; i < rounds; i++)
            {
                // COLUMNS
                _G(ref state[0], ref state[4], ref state[8], ref state[12]);
                _G(ref state[1], ref state[5], ref state[9], ref state[13]);
                _G(ref state[2], ref state[6], ref state[10], ref state[14]);
                _G(ref state[3], ref state[7], ref state[11], ref state[15]);

                // DIAGONALS
                _G(ref state[0], ref state[5], ref state[10], ref state[15]);
                _G(ref state[1], ref state[6], ref state[11], ref state[12]);
                _G(ref state[2], ref state[7], ref state[8], ref state[13]);
                _G(ref state[3], ref state[4], ref state[9], ref state[14]);
            }
        } 

        public static UInt64[] _init(byte[] Key, byte[] Nonce, byte Rounds, // l
         byte Parallelism,// p
         short TagSizeBits) // t
        {
            // Fill state with Key, Nonce, Constants { n0, n1, n2, n3, k0, k1, k2, k3, u8, u9, u10, u11, u12, u13, u14, u15}
            UInt64ArrayAsBytes state = new UInt64ArrayAsBytes(16);
            if (Nonce != null)
                Buffer.BlockCopy(Nonce, 0, state.bytes, 0, 4 * sizeof(UInt64));
            UInt64ArrayAsBytes k = new UInt64ArrayAsBytes(Key); // this is used again after the F process, so keep a copy
            Buffer.BlockCopy(Key, 0, state.bytes, 32, 4 * sizeof(UInt64));
            Buffer.BlockCopy(INIT_CONST, 0, state.bytes, 64, 8 * sizeof(UInt64));
            state.uint64[12] ^= 64;
            state.uint64[13] ^= Rounds;
            state.uint64[14] ^= Parallelism;
            state.uint64[15] ^= (UInt64)TagSizeBits;
            _F(ref state.uint64, Rounds);
            state.uint64[12] ^= k.uint64[0];
            state.uint64[13] ^= k.uint64[1];
            state.uint64[14] ^= k.uint64[2];
            state.uint64[15] ^= k.uint64[3];
            return state.uint64;
        }

        internal static void _absorb(ref UInt64[] state, byte[] payload, byte domain, byte rounds)
        {
            // absorb header, payload, or footer with domain separation constant
            if (payload.LongLength == 0) return;    

            UInt64[] state_buffer = new UInt64[NORX_RateSizeBytes / sizeof(UInt64)];
            for (int i = 0; i < payload.Length + 1; i+= NORX_RateSizeBytes) // the length + 1 ensures the FOR loop runs one additional time
            {
                state[15] ^= (UInt64)domain;
                _F(ref state, rounds);
                state_buffer.Initialize();
                if (i + NORX_RateSizeBytes >= payload.Length)
                {
                    byte[] LastBlock = new byte[NORX_RateSizeBytes];
                    if (i < payload.Length)
                        Buffer.BlockCopy(payload, i, LastBlock, 0, payload.Length % NORX_RateSizeBytes);
                    LastBlock[payload.Length % NORX_RateSizeBytes] = 0x01;
                    LastBlock[LastBlock.Length -1] |= 0x80;
                    Buffer.BlockCopy(LastBlock, 0, state_buffer, 0, LastBlock.Length);
                }
                else
                {
                    Buffer.BlockCopy(payload, i, state_buffer, 0, NORX_RateSizeBytes);
                }
                for (int j = 0; j < state_buffer.Length; j ++)
                {
                    state[j] ^= state_buffer[j];
                };
            }
            
        }

        internal static byte[] _encrypt_block(ref UInt64[] state, byte[] payload_segment, byte rounds)
        {
            state[15] ^= 0x02UL;
            _F(ref state, rounds);
            UInt64ArrayAsBytes output = new UInt64ArrayAsBytes(state);
            UInt64ArrayAsBytes pl = new UInt64ArrayAsBytes(payload_segment);
            for (int i = 0; i < 16; i++)
            {
                output.uint64[i] ^= pl.uint64[i];
            }
            state = output.uint64;
            return output.bytes;
        }

        internal static byte[] _encrypt(ref UInt64[] state, byte[] payload, byte rounds)
        {
            // absorb header, payload, or footer with domain separation constant
            if (payload == null || payload.LongLength == 0) return null;
            byte[] output = new byte[payload.Length];

            UInt64[] state_buffer = new UInt64[NORX_RateSizeBytes / sizeof(UInt64)];
            for (int i = 0; i < payload.Length + 1; i += NORX_RateSizeBytes) // the length + 1 ensures the FOR loop runs one additional time
            {
                state_buffer.Initialize();
                if (i + NORX_RateSizeBytes >= payload.Length)
                {
                    byte[] LastBlock = new byte[NORX_RateSizeBytes];
                    if (i < payload.Length)
                        Buffer.BlockCopy(payload, i, LastBlock, 0, payload.Length % NORX_RateSizeBytes);
                    LastBlock[payload.Length % NORX_RateSizeBytes] = 0x01;
                    LastBlock[LastBlock.Length - 1] |= 0x80;
                    Buffer.BlockCopy(LastBlock, 0, state_buffer, 0, LastBlock.Length);
                }
                else
                {
                    Buffer.BlockCopy(payload, i, state_buffer, 0, NORX_RateSizeBytes);
                }
                for (int j = 0; j < state_buffer.Length; j++)
                {
                    state[j] ^= state_buffer[j];
                };
                if (i + NORX_RateSizeBytes >= payload.Length)
                    Buffer.BlockCopy(state, 0, output, i, payload.Length % NORX_RateSizeBytes);
                else
                    Buffer.BlockCopy(state, 0, output, i, NORX_RateSizeBytes);
            }
            return output;
        }

        internal static void _branch(ref UInt64[] lane_state, byte lane, byte rounds)
        {
            lane_state[15] ^= 0x10UL;
            _F(ref lane_state, rounds);
            for (int i = 0; i < lane_state.Length; i++)
            {
                lane_state[i] ^= (UInt64)lane;
            }
        }

        internal static void _merge(ref UInt64[] state, UInt64ArrayAsBytes[] lane_state, Int64 payloadLength)
        {
            // marge a branch back into the process with domain separation constant 0x20
            return;
        }

        internal static byte[] _finalize(ref UInt64[] state, UInt64ArrayAsBytes k, byte rounds, short tagsizebits)
        {
            byte[] lastblock = new byte [NORX_CapacitySizeBytes];

            state[15] ^= 0x08UL; // 'tag' domain
            _F(ref state, rounds);

            state[12] ^= k.uint64[0];
            state[13] ^= k.uint64[1];
            state[14] ^= k.uint64[2];
            state[15] ^= k.uint64[3];

            _F(ref state, rounds);

            state[12] ^= k.uint64[0];
            state[13] ^= k.uint64[1];
            state[14] ^= k.uint64[2];
            state[15] ^= k.uint64[3];

            Buffer.BlockCopy(state, 12 * sizeof(UInt64), lastblock, 0, tagsizebits / 8);

            state.Initialize(); // zero out some memory
            state[0] ^= state[1]; // prevent compiler from optimizing out the zeroing
            k.uint64.Initialize();
            k.bytes[0] ^= k.bytes[1]; // prevent compiler from optimizing out the zeroing
            lastblock[0] ^= k.bytes[0];
            return lastblock;
        }

        internal static bool _finalize(ref UInt64[] state, byte[] K, byte[] T)
        {
            
            return false;
        }

        #endregion // CORE FUNCTIONS


    }
}
