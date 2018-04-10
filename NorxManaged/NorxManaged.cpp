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

#include "NorxManaged.h"
#include "NorxCore32.cpp"
#include "NorxCore64.cpp"

namespace NorxManaged
{
	// 32 BIT PUBLIC METHODS
	int NorxManaged::Norx32::Encrypt(
		array<const Byte>^ Header,
		array<const Byte>^ Message,
		array<const Byte>^ Trailer,
		array<const Byte>^ Key,
		array<const Byte>^ Nonce,
		const Byte Rounds,
		const Byte Parallelism,
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
		Output = gcnew array<Byte>(Message != nullptr ? Message->LongLength + NORX32_TAGBYTES : NORX32_TAGBYTES);
		if (Parallelism == 1)
		{
			NorxCore32::_encrypt_p1(state, Message, PAYLOAD_TAG, Rounds, Output);
		}
		else if (Parallelism > 1)
		{
			array<array<UInt32>^>^ lanes = gcnew array<array<UInt32>^>(Parallelism);
			for (Byte i = 0; i < Parallelism; i++)
			{
				lanes[i] = (array<UInt32>^)state->Clone();
				NorxManaged::NorxCore32::_branch(lanes[i], i, Rounds);
			}
			NorxCore32::_encrypt_p2(lanes, Message, PAYLOAD_TAG, Rounds, Parallelism, Output);
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

	int NorxManaged::Norx32::DecryptVerify(
		array<const Byte>^ Header,
		array<const Byte>^ Message,
		array<const Byte>^ Trailer,
		array<const Byte>^ Key,
		array<const Byte>^ Nonce,
		const Byte Rounds,
		const Byte Parallelism,
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
		if (Message == nullptr || Message->LongLength == 0)
			throw gcnew ArgumentNullException("Message", "Message cannot be NULL, and must be at least (TagBitSize / 8) bytes in length.");
		array<UInt32>^ kt = gcnew array<UInt32>(NORX32_KEYWORDS);
		Buffer::BlockCopy(Key, 0, kt, 0, NORX32_KEYBYTES);
		array<UInt32>^ state = gcnew array<UInt32>(NORX32_STATEWORDS);
		NorxManaged::NorxCore32::_init(state, Nonce, (array<const UInt32>^)kt, Rounds, Parallelism, TagBitSize);
		NorxManaged::NorxCore32::_absorb(state, Header, HEADER_TAG, Rounds);
		Output = nullptr;
		if (Message != nullptr)
			Output = Message->LongLength >= NORX32_TAGBYTES ? gcnew array<Byte>(Message->LongLength - NORX32_TAGBYTES) : nullptr;
		if (Parallelism == 1)
		{
			NorxCore32::_decrypt_p1(state, Message, PAYLOAD_TAG, Rounds, TagBitSize / 8, Output);
		}
		else if (Parallelism > 1)
		{
			array<array<UInt32>^>^ lanes = gcnew array<array<UInt32>^>(Parallelism);
			for (Byte i = 0; i < Parallelism; i++)
			{
				lanes[i] = (array<UInt32>^)state->Clone();
				NorxManaged::NorxCore32::_branch(lanes[i], i, Rounds);
			}
			NorxCore32::_decrypt_p2(lanes, Message, PAYLOAD_TAG, Rounds, Parallelism, TagBitSize / 8, Output);
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

	int NorxManaged::Norx32::Encrypt_Detached(
		array<const Byte>^ Header,
		array<const Byte>^ Message,
		array<const Byte>^ Trailer,
		array<const Byte>^ Key,
		array<const Byte>^ Nonce,
		const Byte Rounds,
		const Byte Parallelism,
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
			NorxCore32::_encrypt_p1(state, Message, PAYLOAD_TAG, Rounds, Output);
		}
		else if (Parallelism > 1)
		{
			array<array<UInt32>^>^ lanes = gcnew array<array<UInt32>^>(Parallelism);
			for (Byte i = 0; i < Parallelism; i++)
			{
				lanes[i] = (array<UInt32>^)state->Clone();
				NorxManaged::NorxCore32::_branch(lanes[i], i, Rounds);
			}
			NorxCore32::_encrypt_p2(lanes, Message, PAYLOAD_TAG, Rounds, Parallelism, Output);
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

	int NorxManaged::Norx32::DecryptVerify_Detached(
		array<const Byte>^ Header,
		array<const Byte>^ Message,
		array<const Byte>^ Trailer,
		array<const Byte>^ Key,
		array<const Byte>^ Nonce,
		const Byte Rounds,
		const Byte Parallelism,
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
			Output = gcnew array<Byte>(Message->LongLength);

		if (Parallelism == 1)
		{
			NorxCore32::_decrypt_p1(state, Message, PAYLOAD_TAG, Rounds, 0, Output);
		}
		else if (Parallelism > 1)
		{
			array<array<UInt32>^>^ lanes = gcnew array<array<UInt32>^>(Parallelism);
			for (Byte i = 0; i < Parallelism; i++)
			{
				lanes[i] = (array<UInt32>^)state->Clone();
				NorxManaged::NorxCore32::_branch(lanes[i], i, Rounds);
			}
			NorxCore32::_decrypt_p2(lanes, Message, PAYLOAD_TAG, Rounds, Parallelism, 0, Output);
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

	// 64 BIT PUBLIC METHODS =====================================================================================================================================================
	int NorxManaged::Norx64::Encrypt(
		array<const Byte>^ Header,
		array<const Byte>^ Message,
		array<const Byte>^ Trailer,
		array<const Byte>^ Key,
		array<const Byte>^ Nonce,
		const Byte Rounds,
		const Byte Parallelism,
		const short TagBitSize,
		[Out] array<Byte>^% Output)
	{
		if (Key == nullptr || Key->Length != NORX64_KEYBYTES)
			throw gcnew InvalidOperationException("Key not optional. Must be " + NORX64_KEYBYTES + " bytes.");
		if (Nonce == nullptr && Nonce->Length != NORX64_NONCEBYTES)
			throw gcnew InvalidOperationException("Nonce is optional, but must be " + NORX64_NONCEBYTES + " when specified.");
		if (Rounds < 4)
			throw gcnew ArgumentOutOfRangeException("Rounds", "Rounds are limited to a minimum of 4.");
		if (Parallelism == 0)
			throw gcnew NotImplementedException("Parallelism must be > 0.");
		if (TagBitSize == 0 || TagBitSize % 8 != 0)
			throw gcnew ArgumentOutOfRangeException("TagBitSize", "Tag length must be specified as a multiple of 8 bits, and (0 < x <= " + NORX64_TAGBYTES * 8 + ").");
		array<UInt64>^ kt = gcnew array<UInt64>(NORX64_KEYWORDS);
		Buffer::BlockCopy(Key, 0, kt, 0, NORX64_KEYBYTES);
		array<UInt64>^ state = gcnew array<UInt64>(NORX64_STATEWORDS);
		NorxManaged::NorxCore64::_init(state, Nonce, (array<const UInt64>^)kt, Rounds, Parallelism, TagBitSize);
		NorxManaged::NorxCore64::_absorb(state, Header, HEADER_TAG, Rounds);
		Output = gcnew array<Byte>(Message != nullptr ? Message->LongLength + NORX64_TAGBYTES : NORX64_TAGBYTES);
		if (Parallelism == 1)
		{
			NorxCore64::_encrypt_p1(state, Message, PAYLOAD_TAG, Rounds, Output);
		}
		else if (Parallelism > 1)
		{
			array<array<UInt64>^>^ lanes = gcnew array<array<UInt64>^>(Parallelism);
			for (Byte i = 0; i < Parallelism; i++)
			{
				lanes[i] = (array<UInt64>^)state->Clone();
				NorxManaged::NorxCore64::_branch(lanes[i], i, Rounds);
			}
			NorxCore64::_encrypt_p2(lanes, Message, PAYLOAD_TAG, Rounds, Parallelism, Output);
			NorxCore64::_burn(state);
			for (Byte i = 0; i < Parallelism; i++)
			{
				NorxCore64::_merge(state, lanes[i], Rounds);
				NorxCore64::_burn(lanes[i]);
			}
		}
		//else // Infinite parallelism not implemented (p=0)
		//{ }
		NorxManaged::NorxCore64::_absorb(state, Trailer, TRAILER_TAG, Rounds);
		array<Byte>^ tempTag = gcnew array<Byte>(NORX64_TAGBYTES);
		NorxManaged::NorxCore64::_finalize(state, (array<const UInt64>^)kt, Rounds, TagBitSize, tempTag);
		Buffer::BlockCopy(tempTag, 0, Output, Output->Length - NORX64_TAGBYTES, NORX64_TAGBYTES);
		return 0; // OK
	}

	int NorxManaged::Norx64::DecryptVerify(
		array<const Byte>^ Header,
		array<const Byte>^ Message,
		array<const Byte>^ Trailer,
		array<const Byte>^ Key,
		array<const Byte>^ Nonce,
		const Byte Rounds,
		const Byte Parallelism,
		const short TagBitSize,
		[Out] array<Byte>^% Output)
	{
		if (Key == nullptr || Key->Length != NORX64_KEYBYTES)
			throw gcnew InvalidOperationException("Key not optional.  Must be " + NORX64_KEYBYTES + " bytes.");
		if (Nonce == nullptr && Nonce->Length != NORX64_NONCEBYTES)
			throw gcnew InvalidOperationException("Nonce is optional, but must be " + NORX64_NONCEBYTES + " when specified.");
		if (Rounds < 4)
			throw gcnew ArgumentOutOfRangeException("Rounds", "Rounds are limited to a minimum of 4.");
		if (Parallelism == 0)
			throw gcnew NotImplementedException("Parallelism must be > 0.");
		if (TagBitSize == 0 || TagBitSize % 8 != 0)
			throw gcnew ArgumentOutOfRangeException("TagBitSize", "Tag length must be specified as a multiple of 8 bits, and (0 < x <= " + NORX64_TAGBYTES * 8 + ").");
		if (Message == nullptr || Message->LongLength == 0)
			throw gcnew ArgumentNullException("Message", "Message cannot be NULL, and must be at least (TagBitSize / 8) in length.");
		array<UInt64>^ kt = gcnew array<UInt64>(NORX64_KEYWORDS);
		Buffer::BlockCopy(Key, 0, kt, 0, NORX64_KEYBYTES);
		array<UInt64>^ state = gcnew array<UInt64>(NORX64_STATEWORDS);
		NorxManaged::NorxCore64::_init(state, Nonce, (array<const UInt64>^)kt, Rounds, Parallelism, TagBitSize);
		NorxManaged::NorxCore64::_absorb(state, Header, HEADER_TAG, Rounds);
		Output = nullptr;
		if (Message != nullptr)
			Output = Message->LongLength >= NORX64_TAGBYTES ? gcnew array<Byte>(Message->LongLength - NORX64_TAGBYTES) : nullptr;
		if (Parallelism == 1)
		{
			NorxCore64::_decrypt_p1(state, Message, PAYLOAD_TAG, Rounds, TagBitSize / 8, Output);
		}
		else if (Parallelism > 1)
		{
			array<array<UInt64>^>^ lanes = gcnew array<array<UInt64>^>(Parallelism);
			for (Byte i = 0; i < Parallelism; i++)
			{
				lanes[i] = (array<UInt64>^)state->Clone();
				NorxManaged::NorxCore64::_branch(lanes[i], i, Rounds);
			}
			NorxCore64::_decrypt_p2(lanes, Message, PAYLOAD_TAG, Rounds, Parallelism, TagBitSize / 8, Output);
			NorxCore64::_burn(state);
			for (Byte i = 0; i < Parallelism; i++)
			{
				NorxCore64::_merge(state, lanes[i], Rounds);
				NorxCore64::_burn(lanes[i]);
			}
		}
		//else // Infinite parallelism not implemented (p=0)
		//{ }
		NorxManaged::NorxCore64::_absorb(state, Trailer, TRAILER_TAG, Rounds);
		array<Byte>^ temptag = gcnew array<Byte>(TagBitSize / 8);
		array<Byte>^ inputTag = gcnew array<Byte>(TagBitSize / 8);
		Buffer::BlockCopy(Message, Message->LongLength - (TagBitSize / 8), inputTag, 0, TagBitSize / 8);
		NorxManaged::NorxCore64::_finalize(state, (array<const UInt64>^)kt, Rounds, TagBitSize, temptag);
		if (NorxManaged::NorxCore64::norx_verify_tag((array<const Byte>^)inputTag, (array<const Byte>^)temptag) == 0)
			return 0; // OK
		else
		{
			NorxCore64::_burn(Output);
			Output = nullptr;
			return -1;
		}
	}

	int NorxManaged::Norx64::Encrypt_Detached(
		array<const Byte>^ Header,
		array<const Byte>^ Message,
		array<const Byte>^ Trailer,
		array<const Byte>^ Key,
		array<const Byte>^ Nonce,
		const Byte Rounds,
		const Byte Parallelism,
		const short TagBitSize,
		[Out] array<Byte>^% Output,
		[Out] array<Byte>^% Tag)
	{
		if (Key == nullptr || Key->Length != NORX64_KEYBYTES)
			throw gcnew InvalidOperationException("Key not optional. Must be " + NORX64_KEYBYTES + " bytes.");
		if (Nonce == nullptr && Nonce->Length != NORX64_NONCEBYTES)
			throw gcnew InvalidOperationException("Nonce is optional, but must be " + NORX64_NONCEBYTES + " when specified.");
		if (Rounds < 4)
			throw gcnew ArgumentOutOfRangeException("Rounds", "Rounds are limited to a minimum of 4.");
		if (Parallelism == 0)
			throw gcnew NotImplementedException("Parallelism must be > 0.");
		if (TagBitSize == 0 || TagBitSize % 8 != 0)
			throw gcnew ArgumentOutOfRangeException("TagBitSize", "Tag length must be specified as a multiple of 8, and (0 < x <= " + NORX64_TAGBYTES * 8 + ").");
		//if (output_tag == nullptr || output_tag->Length * 8 != TagBitSize)
		//	throw gcnew ArgumentOutOfRangeException("output_tag", "The Tag buffer must be allocated by the caller, and be the same bit size as specified in TagBitSize.");
		Tag = gcnew array<Byte>(NORX64_TAGBYTES);
		Output = Message != nullptr ? gcnew array<Byte>( Message->Length) : nullptr;
		array<UInt64>^ kt = gcnew array<UInt64>(NORX64_KEYWORDS);
		Buffer::BlockCopy(Key, 0, kt, 0, NORX64_KEYBYTES);
		array<UInt64>^ state = gcnew array<UInt64>(NORX64_STATEWORDS);
		NorxManaged::NorxCore64::_init(state, Nonce, (array<const UInt64>^)kt, Rounds, Parallelism, TagBitSize);
		NorxManaged::NorxCore64::_absorb(state, Header, HEADER_TAG, Rounds);
		if (Message != nullptr)
			Output = gcnew array<Byte>(Message->LongLength);
		if (Parallelism == 1)
		{
			NorxCore64::_encrypt_p1(state, Message, PAYLOAD_TAG, Rounds, Output);
		}
		else if (Parallelism > 1)
		{
			array<array<UInt64>^>^ lanes = gcnew array<array<UInt64>^>(Parallelism);
			for (Byte i = 0; i < Parallelism; i++)
			{
				lanes[i] = (array<UInt64>^)state->Clone();
				NorxManaged::NorxCore64::_branch(lanes[i], i, Rounds);
			}
			NorxCore64::_encrypt_p2(lanes, Message, PAYLOAD_TAG, Rounds, Parallelism, Output);
			NorxCore64::_burn(state);
			for (Byte i = 0; i < Parallelism; i++)
			{
				NorxCore64::_merge(state, lanes[i], Rounds);
				NorxCore64::_burn(lanes[i]);
			}
		}
		//else // Infinite parallelism not implemented (p=0)
		//{ }
		NorxManaged::NorxCore64::_absorb(state, Trailer, TRAILER_TAG, Rounds);
		NorxManaged::NorxCore64::_finalize(state, (array<const UInt64>^)kt, Rounds, TagBitSize, Tag);
		return 0; // OK
	}

	int NorxManaged::Norx64::DecryptVerify_Detached(
		array<const Byte>^ Header,
		array<const Byte>^ Message,
		array<const Byte>^ Trailer,
		array<const Byte>^ Key,
		array<const Byte>^ Nonce,
		const Byte Rounds,
		const Byte Parallelism,
		array<const Byte>^ Tag,
		[Out] array<Byte>^% Output)
	{
		if (Key == nullptr || Key->Length != NORX64_KEYBYTES)
			throw gcnew InvalidOperationException("Key not optional.  Must be " + NORX64_KEYBYTES + " bytes.");
		if (Nonce == nullptr && Nonce->Length != NORX64_NONCEBYTES)
			throw gcnew InvalidOperationException("Nonce is optional, but must be " + NORX64_NONCEBYTES + " when specified.");
		if (Rounds < 4)
			throw gcnew ArgumentOutOfRangeException("Rounds", "Rounds are limited to a minimum of 4.");
		if (Parallelism == 0)
			throw gcnew NotImplementedException("Parallelism must be > 0.");
		if (Tag == nullptr || Tag->Length > NORX64_TAGBYTES)
			throw gcnew ArgumentNullException("Tag", "Tag cannot be NULL or 0 length, and must be less than or equal to " + NORX64_TAGBYTES + " bytes in length.");
		array<UInt64>^ kt = gcnew array<UInt64>(NORX64_KEYWORDS);
		Buffer::BlockCopy(Key, 0, kt, 0, NORX64_KEYBYTES);
		array<UInt64>^ state = gcnew array<UInt64>(NORX64_STATEWORDS);
		NorxManaged::NorxCore64::_init(state, Nonce, (array<const UInt64>^)kt, Rounds, Parallelism, Tag->Length * 8);
		NorxManaged::NorxCore64::_absorb(state, Header, HEADER_TAG, Rounds);
		Output = nullptr;
		if (Message != nullptr)
			Output = gcnew array<Byte>(Message->LongLength);

		if (Parallelism == 1)
		{
			NorxCore64::_decrypt_p1(state, Message, PAYLOAD_TAG, Rounds, 0, Output);
		}
		else if (Parallelism > 1)
		{
			array<array<UInt64>^>^ lanes = gcnew array<array<UInt64>^>(Parallelism);
			for (Byte i = 0; i < Parallelism; i++)
			{
				lanes[i] = (array<UInt64>^)state->Clone();
				NorxManaged::NorxCore64::_branch(lanes[i], i, Rounds);
			}
			NorxCore64::_decrypt_p2(lanes, Message, PAYLOAD_TAG, Rounds, Parallelism, 0, Output);
			NorxCore64::_burn(state);
			for (Byte i = 0; i < Parallelism; i++)
			{
				NorxCore64::_merge(state, lanes[i], Rounds);
				NorxCore64::_burn(lanes[i]);
			}
		}
		//else // Infinite parallelism not implemented (p=0)
		//{ }
		NorxManaged::NorxCore64::_absorb(state, Trailer, TRAILER_TAG, Rounds);
		array<Byte>^ temptag = gcnew array<Byte>(Tag->Length);
		NorxManaged::NorxCore64::_finalize(state, (array<const UInt64>^)kt, Rounds, Tag->Length * 8, temptag);
		if (NorxManaged::NorxCore64::norx_verify_tag(Tag, (array<const Byte>^)temptag) == 0)
		{
			return 0; // ok
		}
		else
		{
			NorxCore64::_burn(Output);
			Output = nullptr;
			return -1;
		}
	}
}