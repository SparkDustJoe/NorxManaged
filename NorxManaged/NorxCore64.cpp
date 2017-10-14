using namespace System::Runtime::InteropServices;

#pragma once

#ifndef NORX_NORX_CORE64
#define NORX_NORX_CORE64
#include <stdlib.h>

namespace NorxManaged
{
	namespace NorxCore64
	{
#define NORX64_WORDBYTES	8
#define NORX64_STATEWORDS	16
#define NORX64_STATEBYTES	128
#define NORX64_NONCEBYTES	32
#define NORX64_NONCEWORDS	4
#define NORX64_KEYBYTES		32
#define NORX64_KEYWORDS		4
#define NORX64_RATEBYTES	96
#define NORX64_RATEWORDS	12
#define NORX64_CAPBYTES		32
#define NORX64_CAPWORDS		4
#define NORX64_TAGBYTES		32
#define NORX64_TAGWORDS		4
#define ROTR64(x, y) _rotr64(x, y)

		// The nonlinear primitive 
#define _H(A, B) ( A ^ B ^ (( (A) & (B) ) << 1) )

// The quarter-round 
#define _G64(A, B, C, D)                               \
{                                                   \
    (A) = _H(A, B); (D) ^= (A); (D) = ROTR64((D), 8); \
    (C) = _H(C, D); (B) ^= (C); (B) = ROTR64((B), 19); \
    (A) = _H(A, B); (D) ^= (A); (D) = ROTR64((D), 40); \
    (C) = _H(C, D); (B) ^= (C); (B) = ROTR64((B), 63); \
}
	//These BURN methods should survive compiler optimization, they are only used at the end of a processes
		static __inline void _burn(array<UInt64>^ thing)
		{
			for (Byte i = 0; i < thing->Length; i++)
			{
				thing[i] = 0;
			}
		}
		static __inline void _burn(array<Byte>^ thing)
		{
			for (int i = 0; i < thing->Length; i++)
			{
				thing[i] = 0;
				if (i = 1)
					thing[i] ^= thing[i - 1];
				if (i = thing->Length - 1)
					thing[0] ^= thing[i];
			}
		}

		static __inline void _F(array<UInt64>^ state, const Byte rounds)
		{
			for (Byte i = 0; i < rounds; i++)
			{
				// Column step 
				_G64(state[0], state[4], state[8], state[12]);
				_G64(state[1], state[5], state[9], state[13]);
				_G64(state[2], state[6], state[10], state[14]);
				_G64(state[3], state[7], state[11], state[15]);
				// Diagonal step 
				_G64(state[0], state[5], state[10], state[15]);
				_G64(state[1], state[6], state[11], state[12]);
				_G64(state[2], state[7], state[8], state[13]);
				_G64(state[3], state[4], state[9], state[14]);
			}
		}

		// Low-level operations 
		static __inline void _init(array<UInt64>^ state, array<const Byte>^ n, array<const UInt64>^ k, Byte rounds, Byte lanes, short tagSizeBits)
		{
			if (n != nullptr)
				Buffer::BlockCopy(n, 0, state, 0, NORX64_NONCEBYTES);
			Buffer::BlockCopy(k, 0, state, NORX64_NONCEBYTES, NORX64_KEYBYTES);

			//instead of using the _F construction twice with 0,1,2...15 as the initial state, use pre-computed constants
			state[8] = 0xB15E641748DE5E6BUL;
			state[9] = 0xAA95E955E10F8410UL;
			state[10] = 0x28D1034441A9DD40UL;
			state[11] = 0x7F31BBF964E93BF5UL;

			//while using pre-computed constants, merge in the parameters to the operation
			state[12] = 0xB5E9E22493DFFB96UL ^ 64UL;
			state[13] = 0xB980C852479FAFBDUL ^ (UInt64)rounds;
			state[14] = 0xDA24516BF55EAFD4UL ^ (UInt64)lanes;
			state[15] = 0x86026AE8536F1501UL ^ (UInt64)tagSizeBits;

			_F(state, rounds);

			state[12] ^= k[0];
			state[13] ^= k[1];
			state[14] ^= k[2];
			state[15] ^= k[3];
		}

		static void _absorb(array<UInt64>^ state, array<const Byte>^ in, const _domain_separator tag, const Byte rounds)
		{
			// Used for P=1, and Header and Footer/Trailer (using appropriate domain separation constant)
			if (in->LongLength == 0) return;
			Int64 outptr = 0;
			array<UInt64>^ state_buffer = gcnew array<UInt64>(NORX64_RATEWORDS);
			for (Int64 i = 0; i < in->LongLength; i += NORX64_RATEBYTES)
			{
				bool last = i + NORX64_RATEBYTES >= in->LongLength;
				if (last)
				{
					array<Byte>^ LastBlock = gcnew array<Byte>(NORX64_RATEBYTES);
					if (i < in->LongLength)
						Buffer::BlockCopy(in, i, LastBlock, 0, in->LongLength % NORX64_RATEBYTES);
					LastBlock[in->LongLength % NORX64_RATEBYTES] = 0x01;
					LastBlock[LastBlock->Length - 1] |= 0x80;
					Buffer::BlockCopy(LastBlock, 0, state_buffer, 0, NORX64_RATEBYTES);
				}
				else
				{
					Buffer::BlockCopy(in, i, state_buffer, 0, NORX64_RATEBYTES);
				}			
				state[15] ^= (UInt64)tag;
				_F(state, rounds);
				for (int j = 0; j < state_buffer->Length; j++)
				{
					state[j] ^= state_buffer[j];
				};
				_burn(state_buffer);
			}
		}

		static void _encrypt_p1(array<UInt64>^ state, array<const Byte>^ in, const _domain_separator tag, const Byte rounds, array<Byte>^ out)
		{
			// Used only for Payload of Parallelism > 1 (not P=0)
			if (in->LongLength == 0) return;
			Int64 outptr = 0;
			array<UInt64>^ state_buffer = gcnew array<UInt64>(NORX64_RATEWORDS);
			for (Int64 i = 0; i < in->LongLength; i += NORX64_RATEBYTES)
			{
				bool last = i + NORX64_RATEBYTES >= in->LongLength;
				_burn(state_buffer);
				if (last)
				{
					array<Byte>^ LastBlock = gcnew array<Byte>(NORX64_RATEBYTES);
					if (i < in->LongLength)
						Buffer::BlockCopy(in, i, LastBlock, 0, in->LongLength % NORX64_RATEBYTES);
					LastBlock[in->LongLength % NORX64_RATEBYTES] = 0x01;
					LastBlock[LastBlock->Length - 1] |= 0x80;
					Buffer::BlockCopy(LastBlock, 0, state_buffer, 0, NORX64_RATEBYTES);
				}
				else
				{
					Buffer::BlockCopy(in, i, state_buffer, 0, NORX64_RATEBYTES);
				}
				state[15] ^= (UInt64)tag;
				_F(state, rounds);
				for (int j = 0; j < state_buffer->Length; j++)
				{
					state[j] ^= state_buffer[j];
				};
				if (last)
					Buffer::BlockCopy(state, 0, out, outptr, in->LongLength % NORX64_RATEBYTES);
				else
					Buffer::BlockCopy(state, 0, out, outptr, NORX64_RATEBYTES);
				outptr += NORX64_RATEBYTES;

			}
			_burn(state_buffer);
		}

		static void _decrypt_p1(array<UInt64>^ state, array<const Byte>^ in, const _domain_separator tag, const Byte rounds, array<Byte>^ out)
		{
			// Used only for Payload of Parallelism > 1 (not P=0)
			if (in->LongLength == 0) return;
			Int64 outptr = 0;
			array<UInt64>^ state_buffer = gcnew array<UInt64>(NORX64_RATEWORDS);
			for (Int64 i = 0; i < in->LongLength; i += NORX64_RATEBYTES)
			{
				bool last = i + NORX64_RATEBYTES >= in->LongLength;
				state[15] ^= (UInt64)tag;
				_F(state, rounds);
				if (last)
				{
					array<Byte>^ LastBlock = gcnew array<Byte>(NORX64_RATEBYTES);
					Buffer::BlockCopy(state, 0, LastBlock, 0, NORX64_RATEBYTES); // !!store state in last block, then overwrite with ciphertext
					if (i < in->LongLength)
						Buffer::BlockCopy(in, i, LastBlock, 0, in->LongLength % NORX64_RATEBYTES);
					LastBlock[in->LongLength % NORX64_RATEBYTES] ^= 0x01; // remove the padding
					LastBlock[LastBlock->Length - 1] ^= 0x80;
					Buffer::BlockCopy(LastBlock, 0, state_buffer, 0, NORX64_RATEBYTES);
				}
				else
				{
					Buffer::BlockCopy(in, i, state_buffer, 0, NORX64_RATEBYTES);
				}			
				for (int j = 0; j < state_buffer->Length; j++)
				{
					UInt64 c = state_buffer[j];
					state_buffer[j] ^= state[j];
					state[j] = c;
				};
				if (last)
					Buffer::BlockCopy(state_buffer, 0, out, outptr, in->LongLength % NORX64_RATEBYTES);
				else
					Buffer::BlockCopy(state_buffer, 0, out, outptr, NORX64_RATEBYTES);
				outptr += NORX64_RATEBYTES;
			}
			_burn(state_buffer);
		}

		static void _encrypt_p2(array<array<UInt64>^>^ states, array<const Byte>^ in, const _domain_separator tag, const Byte rounds, const Byte lanes, array<Byte>^ out)
		{
			// Used only for Payload of Parallelism > 1 (not P=0)
			if (in->LongLength == 0) return;
			Int64 outptr = 0;
			Byte laneptr = 0;
			array<UInt64>^ state_buffer = gcnew array<UInt64>(NORX64_RATEWORDS);
			for (Int64 i = 0; i < in->LongLength; i += NORX64_RATEBYTES)
			{
				bool last = i + NORX64_RATEBYTES >= in->LongLength;
				_burn(state_buffer);
				if (last)
				{
					array<Byte>^ LastBlock = gcnew array<Byte>(NORX64_RATEBYTES);
					if (i < in->LongLength)
						Buffer::BlockCopy(in, i, LastBlock, 0, in->LongLength % NORX64_RATEBYTES);
					LastBlock[in->LongLength % NORX64_RATEBYTES] = 0x01;
					LastBlock[LastBlock->Length - 1] |= 0x80;
					Buffer::BlockCopy(LastBlock, 0, state_buffer, 0, LastBlock->Length);
				}
				else
				{
					Buffer::BlockCopy(in, i, state_buffer, 0, NORX64_RATEBYTES);
				}
				states[laneptr][15] ^= (UInt64)tag;
				_F(states[laneptr], rounds);
				for (int j = 0; j < state_buffer->Length; j++)
				{
					// STATE = STATE ^ P = C
					states[laneptr][j] ^= state_buffer[j];
				};
				if (out != nullptr)
				{
					if (last)
						Buffer::BlockCopy(states[laneptr], 0, out, outptr, in->LongLength % NORX64_RATEBYTES);
					else
						Buffer::BlockCopy(states[laneptr], 0, out, outptr, NORX64_RATEBYTES);
					outptr += NORX64_RATEBYTES;
				}
				laneptr = ++laneptr % lanes;
			}
			_burn(state_buffer);
		}

		static void _decrypt_p2(array<array<UInt64>^>^ states, array<const Byte>^ in, const _domain_separator tag, const Byte rounds, const Byte lanes, array<Byte>^ out)
		{
			// Used only for Payload of Parallelism > 1 (not P=0)
			if (in->LongLength == 0) return;
			Int64 outptr = 0;
			Byte laneptr = 0;
			array<UInt64>^ state_buffer = gcnew array<UInt64>(NORX64_RATEWORDS);
			for (Int64 i = 0; i < in->LongLength; i += NORX64_RATEBYTES)
			{
				bool last = i + NORX64_RATEBYTES >= in->LongLength;
				states[laneptr][15] ^= (UInt64)tag;
				_F(states[laneptr], rounds);
				if (last)
				{
					array<Byte>^ LastBlock = gcnew array<Byte>(NORX64_RATEBYTES);
					Buffer::BlockCopy(states[laneptr], 0, LastBlock, 0, NORX64_RATEBYTES); // !!store state in last block, then overwrite with ciphertext
					if (i < in->LongLength)
						Buffer::BlockCopy(in, i, LastBlock, 0, in->LongLength % NORX64_RATEBYTES);
					LastBlock[in->LongLength % NORX64_RATEBYTES] ^= 0x01;
					LastBlock[LastBlock->Length - 1] ^= 0x80;
					Buffer::BlockCopy(LastBlock, 0, state_buffer, 0, LastBlock->Length);
				}
				else
				{
					Buffer::BlockCopy(in, i, state_buffer, 0, NORX64_RATEBYTES);
				}
				for (int j = 0; j < state_buffer->Length; j++)
				{
					// C = (from encryption) P ^ STATE, to recover P then C ^ STATE = P, to recover STATE, then P ^ C
					UInt64 c = state_buffer[j];
					state_buffer[j] ^= states[laneptr][j];
					states[laneptr][j] = c;
				};
				if (last)
					Buffer::BlockCopy(state_buffer, 0, out, outptr, in->LongLength % NORX64_RATEBYTES);
				else
					Buffer::BlockCopy(state_buffer, 0, out, outptr, NORX64_RATEBYTES);
				outptr += NORX64_RATEBYTES;
				laneptr = ++laneptr % lanes;
			}
			_burn(state_buffer);
		}

		static __inline void _branch(array<UInt64>^ state, Byte lane, const Byte rounds)
		{
			state[15] ^= BRANCH_TAG;
			_F(state, rounds);
			// Inject lane ID 
			for (Byte i = 0; i < NORX64_RATEWORDS; ++i) {
				state[i] ^= lane;
			}
		}

		// stateA ^= stateB 
		static __inline void _merge(array<UInt64>^ stateA, array<UInt64>^ stateB, const Byte rounds)
		{
			stateB[15] ^= MERGE_TAG;
			_F(stateB, rounds);
			for (Byte i = 0; i < 16; ++i) {
				stateA[i] ^= stateB[i];
			}
		}

		static __inline void _finalize(array<UInt64>^ state, array<const UInt64>^ k, const Byte rounds, const short tagsizebits, array<Byte>^ out)
		{
			state[15] ^= FINAL_TAG;

			_F(state, rounds);
			state[12] ^= k[0];
			state[13] ^= k[1];
			state[14] ^= k[2];
			state[15] ^= k[3];
			_F(state, rounds);
			state[12] ^= k[0];
			state[13] ^= k[1];
			state[14] ^= k[2];
			state[15] ^= k[3];

			Buffer::BlockCopy(state, 12 * NORX64_WORDBYTES, out, 0, tagsizebits / 8);
			_burn(state); // at this point we can burn the state 
		}

		// Verify tags in constant time: 0 for success, -1 for fail 
		int norx_verify_tag(array<const Byte>^ tag1, array<const Byte>^ tag2)
		{
			unsigned acc = 0;
			for (Byte i = 0; i < NORX64_TAGBYTES; ++i) {
				acc |= tag1[i] ^ tag2[i];
			}

			return (((acc - 1) >> 8) & 1) - 1;
		}
	}
}
#endif // !NORX_NORX_CORE64