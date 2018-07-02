/*
* Modified from NORX reference source code package - reference C implementations
*
* Written 2014-2016 by:
*
*      - Samuel Neves <sneves@dei.uc.pt>
*      - Philipp Jovanovic <philipp@jovanovic.io>
*
* Modified 2017-2018 by:
*      - Dustin Sparks <sparkdustjoe@gmail.com>
*
* To the extent possible under law, the author(s) have dedicated all copyright
* and related and neighboring rights to this software to the public domain
* worldwide. This software is distributed without any warranty.
*
* You should have received a copy of the CC0 Public Domain Dedication along with
* this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include "NorxManaged32.h"
#include "NorxCore32.cpp"

namespace NorxManaged
{
	// 32 BIT PUBLIC METHODS
	int NorxManaged::Norx32::Encrypt(
		array<const Byte>^ Header,
		array<const Byte>^ Message, int Index, int Length,
		array<const Byte>^ Trailer,
		array<const Byte>^ Key, array<const Byte>^ Nonce,
		const Byte Rounds, const Byte Parallelism,
		const short TagBitSize,
		[Out] array<Byte>^% Output)
	{
		if (Key == nullptr || Key->Length != NORX32_KEYBYTES)
			throw gcnew InvalidOperationException("Key not optional. Must be " + NORX32_KEYBYTES + " bytes.");
		if (Nonce == nullptr && Nonce->Length != NORX32_NONCEBYTES)
			throw gcnew InvalidOperationException("Nonce is optional, but must be " + NORX32_NONCEBYTES + " when specified.");
		if (Rounds < 4)
			throw gcnew ArgumentOutOfRangeException("Rounds", "Rounds are limited to a minimum of 4.");
		if (Parallelism == 0)
			throw gcnew NotImplementedException("Parallelism must be > 0.");
		if (TagBitSize == 0 || TagBitSize % 8 != 0)
			throw gcnew ArgumentOutOfRangeException("TagBitSize", "Tag length must be specified as a multiple of 8 bits, and (0 < x <= " + NORX32_TAGBYTES * 8 + ").");
		array<UInt32>^ kt = gcnew array<UInt32>(NORX32_KEYWORDS);
		Buffer::BlockCopy(Key, 0, kt, 0, NORX32_KEYBYTES);
		array<UInt32>^ state = gcnew array<UInt32>(NORX32_STATEWORDS);
		NorxManaged::NorxCore32::_init(state, Nonce, (array<const UInt32>^)kt, Rounds, Parallelism, TagBitSize);
		NorxManaged::NorxCore32::_absorb(state, Header, HEADER_TAG, Rounds);
		Output = gcnew array<Byte>(Message != nullptr ? Length + NORX32_TAGBYTES : NORX32_TAGBYTES);
		if (Parallelism == 1)
		{
			NorxCore32::_encrypt_p1(state, Message, Index, Length, PAYLOAD_TAG, Rounds, Output, 0);
		}
		else if (Parallelism > 1)
		{
			array<array<UInt32>^>^ lanes = gcnew array<array<UInt32>^>(Parallelism);
			for (Byte i = 0; i < Parallelism; i++)
			{
				lanes[i] = (array<UInt32>^)state->Clone();
				NorxManaged::NorxCore32::_branch(lanes[i], i, Rounds);
			}
			NorxCore32::_encrypt_p2(lanes, Message, Index, Length, PAYLOAD_TAG, Rounds, Parallelism, Output, 0);
			NorxCore32::_burn(state);
			for (Byte i = 0; i < Parallelism; i++)
			{
				NorxCore32::_merge(state, lanes[i], Rounds);
				NorxCore32::_burn(lanes[i]);
			}
		}
		//else // Infinite parallelism not implemented (p=0)
		//{ }
		NorxManaged::NorxCore32::_absorb(state, Trailer, TRAILER_TAG, Rounds);
		array<Byte>^ tempTag = gcnew array<Byte>(NORX32_TAGBYTES);
		NorxManaged::NorxCore32::_finalize(state, (array<const UInt32>^)kt, Rounds, TagBitSize, tempTag);
		Buffer::BlockCopy(tempTag, 0, Output, Output->Length - NORX32_TAGBYTES, NORX32_TAGBYTES);
		return 0; // OK
	}

	int NorxManaged::Norx32::Encrypt(
		array<const Byte>^ Header, array<const Byte>^ Message, array<const Byte>^ Trailer,
		array<const Byte>^ Key, array<const Byte>^ Nonce,
		const Byte Rounds, const Byte Parallelism,
		const short TagBitSize,
		[Out] array<Byte>^% Output)
	{
		return NorxManaged::Norx32::Encrypt(Header, Message, 0, Message == nullptr ? 0 : Message->Length, Trailer, Key, Nonce, Rounds, Parallelism, TagBitSize, Output);
	}

	int NorxManaged::Norx32::DecryptVerify(
		array<const Byte>^ Header,
		array<const Byte>^ Message, int Index, int Length,
		array<const Byte>^ Trailer,
		array<const Byte>^ Key, array<const Byte>^ Nonce,
		const Byte Rounds, const Byte Parallelism,
		const short TagBitSize,
		[Out] array<Byte>^% Output)
	{
		if (Key == nullptr || Key->Length != NORX32_KEYBYTES)
			throw gcnew InvalidOperationException("Key not optional.  Must be " + NORX32_KEYBYTES + " bytes.");
		if (Nonce == nullptr && Nonce->Length != NORX32_NONCEBYTES)
			throw gcnew InvalidOperationException("Nonce is optional, but must be " + NORX32_NONCEBYTES + " when specified.");
		if (Rounds < 4)
			throw gcnew ArgumentOutOfRangeException("Rounds", "Rounds are limited to a minimum of 4.");
		if (Parallelism == 0)
			throw gcnew NotImplementedException("Parallelism must be > 0.");
		if (TagBitSize == 0 || TagBitSize % 8 != 0)
			throw gcnew ArgumentOutOfRangeException("TagBitSize", "Tag length must be specified as a multiple of 8 bits, and (0 < x <= " + NORX32_TAGBYTES * 8 + ").");
		if (Message == nullptr || Message->LongLength < TagBitSize / 8 || Length < TagBitSize / 8)
			throw gcnew ArgumentNullException("Message", "Message cannot be NULL, and must be at least (TagBitSize / 8) bytes in length.");
		array<UInt32>^ kt = gcnew array<UInt32>(NORX32_KEYWORDS);
		Buffer::BlockCopy(Key, 0, kt, 0, NORX32_KEYBYTES);
		array<UInt32>^ state = gcnew array<UInt32>(NORX32_STATEWORDS);
		NorxManaged::NorxCore32::_init(state, Nonce, (array<const UInt32>^)kt, Rounds, Parallelism, TagBitSize);
		NorxManaged::NorxCore32::_absorb(state, Header, HEADER_TAG, Rounds);
		Output = nullptr;
		if (Message != nullptr)
			Output = (Length >= NORX32_TAGBYTES) ? gcnew array<Byte>(Length - NORX32_TAGBYTES) : nullptr;
		if (Parallelism == 1)
		{
			NorxCore32::_decrypt_p1(state, Message, Index, Length, PAYLOAD_TAG, Rounds, TagBitSize / 8, Output, 0);
		}
		else if (Parallelism > 1)
		{
			array<array<UInt32>^>^ lanes = gcnew array<array<UInt32>^>(Parallelism);
			for (Byte i = 0; i < Parallelism; i++)
			{
				lanes[i] = (array<UInt32>^)state->Clone();
				NorxManaged::NorxCore32::_branch(lanes[i], i, Rounds);
			}
			NorxCore32::_decrypt_p2(lanes, Message, Index, Length, PAYLOAD_TAG, Rounds, Parallelism, TagBitSize / 8, Output, 0);
			NorxCore32::_burn(state);
			for (Byte i = 0; i < Parallelism; i++)
			{
				NorxCore32::_merge(state, lanes[i], Rounds);
				NorxCore32::_burn(lanes[i]);
			}
		}
		//else // Infinite parallelism not implemented (p=0)
		//{ }
		NorxManaged::NorxCore32::_absorb(state, Trailer, TRAILER_TAG, Rounds);
		array<Byte>^ temptag = gcnew array<Byte>(TagBitSize / 8);
		array<Byte>^ inputTag = gcnew array<Byte>(TagBitSize / 8);
		Buffer::BlockCopy(Message, Message->LongLength - (TagBitSize / 8), inputTag, 0, TagBitSize / 8);
		NorxManaged::NorxCore32::_finalize(state, (array<const UInt32>^)kt, Rounds, TagBitSize, temptag);
		if (NorxManaged::NorxCore32::norx_verify_tag((array<const Byte>^)inputTag, (array<const Byte>^)temptag) == 0)
			return 0; // OK
		else
		{
			NorxCore32::_burn(Output);
			Output = nullptr;
			return -1;
		}
	}

	int NorxManaged::Norx32::DecryptVerify(
		array<const Byte>^ Header, array<const Byte>^ Message, array<const Byte>^ Trailer,
		array<const Byte>^ Key, array<const Byte>^ Nonce,
		const Byte Rounds, const Byte Parallelism,
		const short TagBitSize,
		[Out] array<Byte>^% Output)
	{
		return NorxManaged::Norx32::DecryptVerify(Header, Message, 0, Message == nullptr ? 0 : Message->Length, Trailer, Key, Nonce, Rounds, Parallelism, TagBitSize, Output);
	}

	int NorxManaged::Norx32::Encrypt_Detached(
		array<const Byte>^ Header,
		array<const Byte>^ Message, int Index, int Length,
		array<const Byte>^ Trailer,
		array<const Byte>^ Key, array<const Byte>^ Nonce,
		const Byte Rounds, const Byte Parallelism,
		const short TagBitSize,
		[Out] array<Byte>^% Output,
		[Out] array<Byte>^% Tag)
	{
		if (Key == nullptr || Key->Length != NORX32_KEYBYTES)
			throw gcnew InvalidOperationException("Key not optional. Must be " + NORX32_KEYBYTES + " bytes.");
		if (Nonce == nullptr && Nonce->Length != NORX32_NONCEBYTES)
			throw gcnew InvalidOperationException("Nonce is optional, but must be " + NORX32_NONCEBYTES + " when specified.");
		if (Rounds < 4)
			throw gcnew ArgumentOutOfRangeException("Rounds", "Rounds are limited to a minimum of 4.");
		if (Parallelism == 0)
			throw gcnew NotImplementedException("Parallelism must be > 0.");
		if (TagBitSize == 0 || TagBitSize % 8 != 0)
			throw gcnew ArgumentOutOfRangeException("TagBitSize", "Tag length must be specified as a multiple of 8 bits, and (0 < x <= " + NORX32_TAGBYTES * 8 + ").");
		//if (output_tag == nullptr || output_tag->Length * 8 != TagBitSize)
		//	throw gcnew ArgumentOutOfRangeException("output_tag", "The Tag buffer must be allocated by the caller, and be the same bit size as specified in TagBitSize.");
		Tag = gcnew array<Byte>(NORX32_TAGBYTES);
		Output = Message != nullptr ? gcnew array<Byte>(Message->Length) : nullptr;
		array<UInt32>^ kt = gcnew array<UInt32>(NORX32_KEYWORDS);
		Buffer::BlockCopy(Key, 0, kt, 0, NORX32_KEYBYTES);
		array<UInt32>^ state = gcnew array<UInt32>(NORX32_STATEWORDS);
		NorxManaged::NorxCore32::_init(state, Nonce, (array<const UInt32>^)kt, Rounds, Parallelism, TagBitSize);
		NorxManaged::NorxCore32::_absorb(state, Header, HEADER_TAG, Rounds);
		if (Message != nullptr)
			Output = gcnew array<Byte>(Message->LongLength);
		if (Parallelism == 1)
		{
			NorxCore32::_encrypt_p1(state, Message, Index, Length, PAYLOAD_TAG, Rounds, Output, 0);
		}
		else if (Parallelism > 1)
		{
			array<array<UInt32>^>^ lanes = gcnew array<array<UInt32>^>(Parallelism);
			for (Byte i = 0; i < Parallelism; i++)
			{
				lanes[i] = (array<UInt32>^)state->Clone();
				NorxManaged::NorxCore32::_branch(lanes[i], i, Rounds);
			}
			NorxCore32::_encrypt_p2(lanes, Message, Index, Length, PAYLOAD_TAG, Rounds, Parallelism, Output, 0);
			NorxCore32::_burn(state);
			for (Byte i = 0; i < Parallelism; i++)
			{
				NorxCore32::_merge(state, lanes[i], Rounds);
				NorxCore32::_burn(lanes[i]);
			}
		}
		//else // Infinite parallelism not implemented (p=0)
		//{ }
		NorxManaged::NorxCore32::_absorb(state, Trailer, TRAILER_TAG, Rounds);
		NorxManaged::NorxCore32::_finalize(state, (array<const UInt32>^)kt, Rounds, TagBitSize, Tag);
		return 0; // OK
	}

	int NorxManaged::Norx32::Encrypt_Detached(
		array<const Byte>^ Header, array<const Byte>^ Message, array<const Byte>^ Trailer,
		array<const Byte>^ Key,	array<const Byte>^ Nonce,
		const Byte Rounds, const Byte Parallelism,
		const short TagBitSize,
		[Out] array<Byte>^% Output,
		[Out] array<Byte>^% Tag)
	{
		return NorxManaged::Norx32::Encrypt_Detached(Header, Message, 0, Message == nullptr ? 0 : Message->Length, Trailer, Key, Nonce, Rounds, Parallelism, TagBitSize, Output, Tag);
	}

	int NorxManaged::Norx32::DecryptVerify_Detached(
		array<const Byte>^ Header,
		array<const Byte>^ Message, int Index, int Length,
		array<const Byte>^ Trailer,
		array<const Byte>^ Key,	array<const Byte>^ Nonce,
		const Byte Rounds, const Byte Parallelism,
		array<const Byte>^ Tag,
		[Out] array<Byte>^% Output)
	{
		if (Key == nullptr || Key->Length != NORX32_KEYBYTES)
			throw gcnew InvalidOperationException("Key not optional.  Must be " + NORX32_KEYBYTES + " bytes.");
		if (Nonce == nullptr && Nonce->Length != NORX32_NONCEBYTES)
			throw gcnew InvalidOperationException("Nonce is optional, but must be " + NORX32_NONCEBYTES + " when specified.");
		if (Rounds < 4)
			throw gcnew ArgumentOutOfRangeException("Rounds", "Rounds are limited to a minimum of 4.");
		if (Parallelism == 0)
			throw gcnew NotImplementedException("Parallelism must be > 0.");
		if (Tag == nullptr || Tag->Length > NORX32_TAGBYTES)
			throw gcnew ArgumentNullException("Tag", "Tag cannot be NULL or 0 length, and must be less than or equal to " + NORX32_TAGBYTES + " bytes in length.");
		array<UInt32>^ kt = gcnew array<UInt32>(NORX32_KEYWORDS);
		Buffer::BlockCopy(Key, 0, kt, 0, NORX32_KEYBYTES);
		array<UInt32>^ state = gcnew array<UInt32>(NORX32_STATEWORDS);
		NorxManaged::NorxCore32::_init(state, Nonce, (array<const UInt32>^)kt, Rounds, Parallelism, Tag->Length * 8);
		NorxManaged::NorxCore32::_absorb(state, Header, HEADER_TAG, Rounds);
		Output = nullptr;
		if (Message != nullptr)
			Output = gcnew array<Byte>(Length);

		if (Parallelism == 1)
		{
			NorxCore32::_decrypt_p1(state, Message, Index, Length, PAYLOAD_TAG, Rounds, 0, Output, 0);
		}
		else if (Parallelism > 1)
		{
			array<array<UInt32>^>^ lanes = gcnew array<array<UInt32>^>(Parallelism);
			for (Byte i = 0; i < Parallelism; i++)
			{
				lanes[i] = (array<UInt32>^)state->Clone();
				NorxManaged::NorxCore32::_branch(lanes[i], i, Rounds);
			}
			NorxCore32::_decrypt_p2(lanes, Message, Index, Length, PAYLOAD_TAG, Rounds, Parallelism, 0, Output, 0);
			NorxCore32::_burn(state);
			for (Byte i = 0; i < Parallelism; i++)
			{
				NorxCore32::_merge(state, lanes[i], Rounds);
				NorxCore32::_burn(lanes[i]);
			}
		}
		//else // Infinite parallelism not implemented (p=0)
		//{ }
		NorxManaged::NorxCore32::_absorb(state, Trailer, TRAILER_TAG, Rounds);
		array<Byte>^ temptag = gcnew array<Byte>(Tag->Length);
		NorxManaged::NorxCore32::_finalize(state, (array<const UInt32>^)kt, Rounds, Tag->Length * 8, temptag);
		if (NorxManaged::NorxCore32::norx_verify_tag(Tag, (array<const Byte>^)temptag) == 0)
		{
			return 0; // ok
		}
		else
		{
			NorxCore32::_burn(Output);
			Output = nullptr;
			return -1;
		}
	}

	int NorxManaged::Norx32::DecryptVerify_Detached(
		array<const Byte>^ Header, array<const Byte>^ Message, array<const Byte>^ Trailer,
		array<const Byte>^ Key, array<const Byte>^ Nonce,
		const Byte Rounds, const Byte Parallelism,
		array<const Byte>^ Tag,
		[Out] array<Byte>^% Output)
	{
		return NorxManaged::Norx32::DecryptVerify_Detached(Header, Message, 0, Message == nullptr ? 0 : Message->Length, Trailer, Key, Nonce, Rounds, Parallelism, Tag, Output);
	}
}