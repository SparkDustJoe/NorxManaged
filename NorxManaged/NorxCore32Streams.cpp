using namespace System::Runtime::InteropServices;

#pragma once

#ifndef NORX_NORX_CORE32_STREAMS
#define NORX_NORX_CORE32_STREAMS
#include <stdlib.h> // only needed for _rotr64 and _lotr

namespace NorxManaged
{
	namespace NorxCore32
	{
#define NORX32_WORDBYTES	4
#define NORX32_STATEWORDS	16
#define NORX32_STATEBYTES	64
#define NORX32_NONCEBYTES	16
#define NORX32_NONCEWORDS	4
#define NORX32_KEYBYTES		16
#define NORX32_KEYWORDS		4
#define NORX32_RATEBYTES	48
#define NORX32_RATEWORDS	12
#define NORX32_CAPBYTES		16
#define NORX32_CAPWORDS		4
#define NORX32_TAGBYTES		16
#define NORX32_TAGWORDS		4
#define ROTR32(x, y) _lrotr(x, y)

// The nonlinear primitive 
#define _H(A, B) ( A ^ B ^ (( (A) & (B) ) << 1) )

// The quarter-round 
#define _G32(A, B, C, D)                               \
{                                                   \
    (A) = _H(A, B); (D) ^= (A); (D) = ROTR32((D), 8); \
    (C) = _H(C, D); (B) ^= (C); (B) = ROTR32((B), 11); \
    (A) = _H(A, B); (D) ^= (A); (D) = ROTR32((D), 16); \
    (C) = _H(C, D); (B) ^= (C); (B) = ROTR32((B), 31); \
}
		//These BURN methods should survive compiler optimization, they are only used at the end of a processes
		//Just in case, reference the source array in the calling function in some meaningful way to keep the references alive before the garbage collecter gets them
		static __inline void _burn(array<UInt32>^ thing)
		{
			for (Byte i = 0; i < thing->Length; i++)
			{
				thing[i] = 0;
				if (i = 1)
					thing[i] ^= thing[i - 1];
				if (i = thing->Length - 1)
					thing[0] ^= thing[i];
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

		static __inline void _F(array<UInt32>^ state, const Byte rounds)
		{
			// normally this would be unrolled for performance, but with variable round amounts, that would be tedious to implement
			for (Byte i = 0; i < rounds; i++)
			{
				// Column step 
				_G32(state[0], state[4], state[8], state[12]);
				_G32(state[1], state[5], state[9], state[13]);
				_G32(state[2], state[6], state[10], state[14]);
				_G32(state[3], state[7], state[11], state[15]);
				// Diagonal step 
				_G32(state[0], state[5], state[10], state[15]);
				_G32(state[1], state[6], state[11], state[12]);
				_G32(state[2], state[7], state[8], state[13]);
				_G32(state[3], state[4], state[9], state[14]);
			}
		}

		// Low-level operations 
		static __inline void _init(array<UInt32>^ state, array<const Byte>^ n, array<const UInt32>^ k, Byte rounds, Byte lanes, short tagSizeBits)
		{
			if (n != nullptr)
				Buffer::BlockCopy(n, 0, state, 0, NORX32_NONCEBYTES);
			Buffer::BlockCopy(k, 0, state, NORX32_NONCEBYTES, NORX32_KEYBYTES);

			//instead of using the _F construction twice with 0,1,2...15 as the initial state, use pre-computed constants
			state[8] = 0xA3D8D930;
			state[9] = 0x3FA8B72C;
			state[10] = 0xED84EB49;
			state[11] = 0xEDCA4787;

			//while using pre-computed constants, merge in the parameters to the operation
			state[12] = 0x335463EB ^ 32L;
			state[13] = 0xF994220B ^ (UInt32)rounds;
			state[14] = 0xBE0BF5C9 ^ (UInt32)lanes;
			state[15] = 0xD7C49104 ^ (UInt32)tagSizeBits;

			_F(state, rounds);

			state[12] ^= k[0];
			state[13] ^= k[1];
			state[14] ^= k[2];
			state[15] ^= k[3];
		}

		static void _absorb(array<UInt32>^ state, MemoryStream^ in, const _domain_separator tag, const Byte rounds)
		{
			// Used for P=1, and Header and Footer/Trailer (using appropriate domain separation constant)
			if (in == nullptr || in->Length == 0) return;
			Int64 outptr = 0;
			array<UInt32>^ state_buffer = gcnew array<UInt32>(NORX32_RATEWORDS);
			array<Byte>^ block = gcnew array<Byte>(NORX32_RATEBYTES);
			for (Int64 i = 0; i < in->Length; i += NORX32_RATEBYTES)
			{
				bool last = i + NORX32_RATEBYTES >= in->Length;	
				if (last)
				{
					_burn(block);
					if (i < in->Length)
						in->Read(block, 0, in->Length % NORX32_RATEBYTES);
						//Buffer::BlockCopy(in, i, LastBlock, 0, in->Length % NORX32_RATEBYTES);
					block[in->Length % NORX32_RATEBYTES] = 0x01;
					block[block->Length - 1] |= 0x80;
					Buffer::BlockCopy(block, 0, state_buffer, 0, NORX32_RATEBYTES);
				}
				else
				{
					in->Read(block, 0, NORX32_RATEBYTES);
					Buffer::BlockCopy(block, 0, state_buffer, 0, NORX32_RATEBYTES);
				}			
				state[15] ^= (UInt32)tag;
				_F(state, rounds);
				for (int j = 0; j < state_buffer->Length; j++)
				{
					state[j] ^= state_buffer[j];
				};
				_burn(state_buffer);
				_burn(block);
				state_buffer[0] ^= state_buffer[1] ^ NORX32_CAPBYTES;
			}
		}

		static void _encrypt_p1(array<UInt32>^ state, MemoryStream^ in, const _domain_separator tag, const Byte rounds, MemoryStream^ out)
		{
			// Used only for Payload of Parallelism = 1 (not P=0)
			if (in == nullptr || in->Length == 0) return;
			array<UInt32>^ state_buffer = gcnew array<UInt32>(NORX32_RATEWORDS);
			array<Byte>^ block = gcnew array<Byte>(NORX32_RATEBYTES);
			for (Int64 i = 0; i < in->Length; i += NORX32_RATEBYTES)
			{
				bool last = i + NORX32_RATEBYTES >= in->Length;
				_burn(state_buffer);
				if (last)
				{
					_burn(block);
					if (i < in->Length)
						in->Read(block, 0, in->Length % NORX32_RATEBYTES);
					block[in->Length % NORX32_RATEBYTES] = 0x01;
					block[block->Length - 1] |= 0x80;
					Buffer::BlockCopy(block, 0, state_buffer, 0, NORX32_RATEBYTES);
				}
				else
				{
					in->Read(block, 0, NORX32_RATEBYTES);
					Buffer::BlockCopy(block, 0, state_buffer, 0, NORX32_RATEBYTES);
				}
				state[15] ^= (UInt32)tag;
				_F(state, rounds);
				for (int j = 0; j < state_buffer->Length; j++)
				{
					state[j] ^= state_buffer[j];
				};
				Buffer::BlockCopy(state, 0, block, 0, NORX32_RATEBYTES);
				if (last)
					out->Write(block, 0, in->Length % NORX32_RATEBYTES);
				else
					out->Write(block, 0, NORX32_RATEBYTES);
			}
			_burn(state_buffer);
			_burn(block);
			state_buffer[0] ^= state_buffer[1] ^ NORX32_CAPBYTES;
		}

		static void _decrypt_p1(array<UInt32>^ state, MemoryStream^ in, const _domain_separator tag, const Byte rounds, int tagBytesInMessage, MemoryStream^ out)
		{
			// Used only for Payload of Parallelism = 1 (not P=0)
			if (in == nullptr || in->Length == 0) return;
			Int64 actualLength = in->Length - tagBytesInMessage;
			array<UInt32>^ state_buffer = gcnew array<UInt32>(NORX32_RATEWORDS);
			array<Byte>^ block = gcnew array<Byte>(NORX32_RATEBYTES);
			for (Int64 i = 0; i < actualLength; i += NORX32_RATEBYTES)
			{
				bool last = i + NORX32_RATEBYTES >= actualLength;
				state[15] ^= (UInt32)tag;
				_F(state, rounds);
				if (last)
				{
					_burn(block);
					Buffer::BlockCopy(state, 0, block, 0, NORX32_RATEBYTES); // !!store state in last block, then overwrite with ciphertext
					if (i < actualLength)
						in->Read(block, 0, actualLength % NORX32_RATEBYTES);
					block[actualLength % NORX32_RATEBYTES] ^= 0x01; // remove the padding
					block[block->Length - 1] ^= 0x80;
					Buffer::BlockCopy(block, 0, state_buffer, 0, NORX32_RATEBYTES);
				}
				else
				{
					in->Read(block, 0, NORX32_RATEBYTES);
					Buffer::BlockCopy(block, 0, state_buffer, 0, NORX32_RATEBYTES);
				}			
				for (int j = 0; j < state_buffer->Length; j++)
				{
					UInt32 c = state_buffer[j];
					state_buffer[j] ^= state[j];
					state[j] = c;
				};
				Buffer::BlockCopy(state_buffer, 0, block, 0, NORX32_RATEBYTES);
				if (last)
					out->Write(block, 0, in->Length % NORX32_RATEBYTES);
				else
					out->Write(block, 0, NORX32_RATEBYTES);
			}
			_burn(state_buffer);
			_burn(block);
			state_buffer[0] ^= state_buffer[1] ^ NORX32_CAPBYTES;
		}

		static void _encrypt_p2(array<array<UInt32>^>^ states, MemoryStream^ in, const _domain_separator tag, const Byte rounds, const Byte lanes, MemoryStream^ out)
		{
			// Used only for Payload of Parallelism > 1 (not P=0)
			if (in == nullptr || in->Length == 0) return;
			Byte laneptr = 0;
			array<UInt32>^ state_buffer = gcnew array<UInt32>(NORX32_RATEWORDS);
			array<Byte>^ block = gcnew array<Byte>(NORX32_RATEBYTES);
			for (Int64 i = 0; i < in->Length; i += NORX32_RATEBYTES)
			{
				bool last = i + NORX32_RATEBYTES >= in->Length;
				_burn(state_buffer);
				if (last)
				{
					_burn(block);
					if (i < in->Length)
						in->Read(block, 0, in->Length % NORX32_RATEBYTES);
					block[in->Length % NORX32_RATEBYTES] = 0x01;
					block[block->Length - 1] |= 0x80;
					Buffer::BlockCopy(block, 0, state_buffer, 0, NORX32_RATEBYTES);
				}
				else
				{
					in->Read(block, 0, NORX32_RATEBYTES);
					Buffer::BlockCopy(block, 0, state_buffer, 0, NORX32_RATEBYTES);
				}
				states[laneptr][15] ^= (UInt32)tag;
				_F(states[laneptr], rounds);
				for (int j = 0; j < state_buffer->Length; j++)
				{
					// STATE = STATE ^ P = C
					states[laneptr][j] ^= state_buffer[j];
				};
				if (out != nullptr)
				{
					Buffer::BlockCopy(states[laneptr], 0, block, 0, NORX32_RATEBYTES);
					if (last)
						out->Write(block, 0, in->Length % NORX32_RATEBYTES);
					else
						out->Write(block, 0, NORX32_RATEBYTES);
				}
				laneptr = ++laneptr % lanes;
			}
			_burn(state_buffer);
			_burn(block);
			state_buffer[0] ^= state_buffer[1] ^ NORX32_CAPBYTES;
		}

		static void _decrypt_p2(array<array<UInt32>^>^ states, MemoryStream^ in, const _domain_separator tag, const Byte rounds, const Byte lanes, int tagBytesInMessage, MemoryStream^ out)
		{
			// Used only for Payload of Parallelism > 1 (not P=0)
			if (in == nullptr || in->Length == 0) return;
			Int64 actualLength = in->Length - tagBytesInMessage;
			Byte laneptr = 0;
			array<UInt32>^ state_buffer = gcnew array<UInt32>(NORX32_RATEWORDS);
			array<Byte>^ block = gcnew array<Byte>(NORX32_RATEBYTES);
			for (Int64 i = 0; i < actualLength; i += NORX32_RATEBYTES)
			{
				bool last = i + NORX32_RATEBYTES >= actualLength;
				states[laneptr][15] ^= (UInt32)tag;
				_F(states[laneptr], rounds);
				if (last)
				{
					_burn(block);
					Buffer::BlockCopy(states[laneptr], 0, block, 0, NORX32_RATEBYTES); // !!store state in last block, then overwrite with ciphertext
					if (i < actualLength)
						in->Read(block, 0, actualLength % NORX32_RATEBYTES);
					block[actualLength % NORX32_RATEBYTES] ^= 0x01;
					block[block->Length - 1] ^= 0x80;
					Buffer::BlockCopy(block, 0, state_buffer, 0, NORX32_RATEBYTES);
				}
				else
				{
					in->Read(block, 0, NORX32_RATEBYTES);
					Buffer::BlockCopy(block, 0, state_buffer, 0, NORX32_RATEBYTES);
				}
				for (int j = 0; j < state_buffer->Length; j++)
				{
					// C = (from encryption) P ^ STATE, to recover P then C ^ STATE = P, to recover STATE, then P ^ C
					UInt32 c = state_buffer[j];
					state_buffer[j] ^= states[laneptr][j];
					states[laneptr][j] = c;
				};
				Buffer::BlockCopy(state_buffer, 0, block, 0, NORX32_RATEBYTES);
				if (last)
					out->Write(block, 0, in->Length % NORX32_RATEBYTES);
				else
					out->Write(block, 0, NORX32_RATEBYTES);
				laneptr = ++laneptr % lanes;
			}
			_burn(state_buffer);
			_burn(block);
			state_buffer[0] ^= state_buffer[1] ^ NORX32_CAPBYTES;
		}

		static __inline void _branch(array<UInt32>^ state, Byte lane, const Byte rounds)
		{
			state[15] ^= BRANCH_TAG;
			_F(state, rounds);
			// Inject lane ID 
			for (Byte i = 0; i < NORX32_RATEWORDS; ++i) {
				state[i] ^= lane;
			}
		}

		// stateA ^= stateB 
		static __inline void _merge(array<UInt32>^ stateA, array<UInt32>^ stateB, const Byte rounds)
		{
			stateB[15] ^= MERGE_TAG;
			_F(stateB, rounds);
			for (Byte i = 0; i < 16; ++i) {
				stateA[i] ^= stateB[i];
			}
		}

		static __inline void _finalize(array<UInt32>^ state, array<const UInt32>^ k, const Byte rounds, const short tagsizebits, MemoryStream^ outTag)
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

			array<Byte>^ tempTag = gcnew array<Byte>(tagsizebits / 8);
			Buffer::BlockCopy(state, NORX32_RATEWORDS * NORX32_WORDBYTES, tempTag, 0, tempTag->Length); // extract Tag
			outTag->Write(tempTag, 0, tempTag->Length);
			_burn(tempTag);
			_burn(state); // at this point we can burn the state 
			state[0] ^= state[1] ^ NORX32_CAPBYTES;
		}

		// Verify tags in constant time: 0 for success, -1 for fail 
		int norx_verify_tag(array<Byte>^ tag1, array<Byte>^ tag2)
		{
			unsigned acc = 0;
			for (Byte i = 0; i < NORX32_TAGBYTES; ++i) {
				acc |= tag1[i] ^ tag2[i];
			}

			return (((acc - 1) >> 8) & 1) - 1;
		}
	}
}
#endif // !NORX_NORX_CORE32