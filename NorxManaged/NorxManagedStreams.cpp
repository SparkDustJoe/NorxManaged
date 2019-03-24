/*
* Modified from NORX reference source code package - reference C implementations
*
* Written 2014-2016 by:
*
*      - Samuel Neves <sneves@dei.uc.pt>
*      - Philipp Jovanovic <philipp@jovanovic.io>
*
* Modified 2017-2019 by:
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
#include "NorxManaged64.h"
#include "NorxCore32Streams.cpp"
#include "NorxCore64Streams.cpp"

namespace NorxManaged
{
	// 32 BIT PUBLIC METHODS
	int NorxManaged::Norx32::EncryptStream(
		MemoryStream^ Header,
		MemoryStream^ Message,
		MemoryStream^ Trailer,
		array<const Byte>^ Key,
		array<const Byte>^ Nonce,
		const Byte Rounds,
		const Byte Parallelism,
		const short TagBitSize,
		MemoryStream^ Output)
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
		array<const UInt32>^ kt = reinterpret_cast<array<const UInt32>^>(Key); // prevent unneccessary memory copying of the key!
		//array<UInt32>^ kt = gcnew array<UInt32>(NORX32_KEYWORDS);
		//Buffer::BlockCopy(Key, 0, kt, 0, NORX32_KEYBYTES);
		array<UInt32>^ state = gcnew array<UInt32>(NORX32_STATEWORDS);
		NorxManaged::NorxCore32::_init(state, Nonce, kt, Rounds, Parallelism, TagBitSize);
		NorxManaged::NorxCore32::_absorb(state, Header, HEADER_TAG, Rounds);
		//Output = gcnew array<Byte>(Message != nullptr ? Message->Length + NORX32_TAGBYTES : NORX32_TAGBYTES);
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
				NorxCore32::_merge(state, lanes[i], Rounds); // merge back into the main state and destroy the lane
			}
		}
		//else // Infinite parallelism not implemented (p=0)
		//{ }
		NorxManaged::NorxCore32::_absorb(state, Trailer, TRAILER_TAG, Rounds);
		NorxManaged::NorxCore32::_finalize(state, kt, Rounds, TagBitSize, Output);
		kt = nullptr;
		return 0; // OK
	}

	int NorxManaged::Norx32::DecryptVerifyStream(
		MemoryStream^ Header,
		MemoryStream^ Message,
		MemoryStream^ Trailer,
		array<const Byte>^ Key,
		array<const Byte>^ Nonce,
		const Byte Rounds,
		const Byte Parallelism,
		const short TagBitSize,
		MemoryStream^ Output)
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
		if (Message == nullptr || Message->Length == 0)
			throw gcnew ArgumentNullException("Message", "Message cannot be NULL, and must be at least (TagBitSize / 8) bytes in length.");
		array<const UInt32>^ kt = reinterpret_cast<array<const UInt32>^>(Key); // prevent unneccessary memory copying of the key!
		//array<UInt32>^ kt = gcnew array<UInt32>(NORX32_KEYWORDS);
		//Buffer::BlockCopy(Key, 0, kt, 0, NORX32_KEYBYTES);
		array<UInt32>^ state = gcnew array<UInt32>(NORX32_STATEWORDS);
		NorxManaged::NorxCore32::_init(state, Nonce, kt, Rounds, Parallelism, TagBitSize);
		NorxManaged::NorxCore32::_absorb(state, Header, HEADER_TAG, Rounds);
		//Output = nullptr;
		//if (Message != nullptr)
		//	Output = Message->Length >= NORX32_TAGBYTES ? gcnew array<Byte>(Message->Length - NORX32_TAGBYTES) : nullptr;
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
				NorxCore32::_merge(state, lanes[i], Rounds); // merge back into the main state and destroy the lane
			}
		}
		//else // Infinite parallelism not implemented (p=0)
		//{ }
		NorxManaged::NorxCore32::_absorb(state, Trailer, TRAILER_TAG, Rounds);
		array<Byte>^ inputTag = gcnew array<Byte>(TagBitSize / 8);
		Message->Write(inputTag, 0, TagBitSize / 8);
		MemoryStream^ tempTag = gcnew MemoryStream(TagBitSize / 8);
		NorxManaged::NorxCore32::_finalize(state, kt, Rounds, TagBitSize, tempTag);
		int returnValue = -1;
		if (NorxManaged::NorxCore32::norx_verify_tag(inputTag, tempTag->GetBuffer()) == 0)
			returnValue = 0; // OK
		else
		{
			NorxCore32::_burn(Output->GetBuffer());
			Output->Flush();
			Threading::Thread::MemoryBarrier();
			//Output->Dispose();
			returnValue = -1;
		}
		NorxCore32::_burn(tempTag->GetBuffer());
		NorxCore32::_burn(inputTag);
		kt = nullptr;
		return returnValue;
	}

	int NorxManaged::Norx32::EncryptStream_Detached(
		MemoryStream^ Header,
		MemoryStream^ Message,
		MemoryStream^ Trailer,
		array<const Byte>^ Key,
		array<const Byte>^ Nonce,
		const Byte Rounds,
		const Byte Parallelism,
		const short TagBitSize,
		MemoryStream^ Output,
		MemoryStream^ Tag)
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
		//Tag = gcnew array<Byte>(NORX32_TAGBYTES);
		//Output = Message != nullptr ? gcnew array<Byte>(Message->Length) : nullptr;
		array<const UInt32>^ kt = reinterpret_cast<array<const UInt32>^>(Key); // prevent unneccessary memory copying of the key!
		//array<UInt32>^ kt = gcnew array<UInt32>(NORX32_KEYWORDS);
		//Buffer::BlockCopy(Key, 0, kt, 0, NORX32_KEYBYTES);
		array<UInt32>^ state = gcnew array<UInt32>(NORX32_STATEWORDS);
		NorxManaged::NorxCore32::_init(state, Nonce, kt, Rounds, Parallelism, TagBitSize);
		NorxManaged::NorxCore32::_absorb(state, Header, HEADER_TAG, Rounds);
		//if (Message != nullptr)
		//	Output = gcnew array<Byte>(Message->Length);
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
				NorxCore32::_merge(state, lanes[i], Rounds); // merge back into the main state and destroy the lane
			}
		}
		//else // Infinite parallelism not implemented (p=0)
		//{ }
		NorxManaged::NorxCore32::_absorb(state, Trailer, TRAILER_TAG, Rounds);
		NorxManaged::NorxCore32::_finalize(state, kt, Rounds, TagBitSize, Tag);
		kt = nullptr;
		return 0; // OK
	}

	int NorxManaged::Norx32::DecryptVerifyStream_Detached(
		MemoryStream^  Header,
		MemoryStream^  Message,
		MemoryStream^  Trailer,
		array<const Byte>^  Key,
		array<const Byte>^  Nonce,
		const Byte Rounds,
		const Byte Parallelism,
		array<const Byte>^ Tag,
		MemoryStream^  Output)
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
		array<const UInt32>^ kt = reinterpret_cast<array<const UInt32>^>(Key); // prevent unneccessary memory copying of the key!
		//array<UInt32>^ kt = gcnew array<UInt32>(NORX32_KEYWORDS);
		//Buffer::BlockCopy(Key, 0, kt, 0, NORX32_KEYBYTES);
		array<UInt32>^ state = gcnew array<UInt32>(NORX32_STATEWORDS);
		NorxManaged::NorxCore32::_init(state, Nonce, kt, Rounds, Parallelism, Tag->Length * 8);
		NorxManaged::NorxCore32::_absorb(state, Header, HEADER_TAG, Rounds);
		//Output = nullptr;
		//if (Message != nullptr)
		//	Output = gcnew array<Byte>(Message->Length);

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
				NorxCore32::_merge(state, lanes[i], Rounds); // merge back into the main state and destroy the lane
			}
		}
		//else // Infinite parallelism not implemented (p=0)
		//{ }
		NorxManaged::NorxCore32::_absorb(state, Trailer, TRAILER_TAG, Rounds);
		MemoryStream^ tempTag = gcnew MemoryStream(Tag->Length);
		NorxManaged::NorxCore32::_finalize(state, kt, Rounds, Tag->Length * 8, tempTag);
		int returnValue = -1;
		if (NorxManaged::NorxCore32::norx_verify_tag((array<Byte>^)Tag, tempTag->GetBuffer()) == 0)
			returnValue = 0; // ok
		else
		{
			NorxCore32::_burn(Output->GetBuffer());
			Output->Flush();
			Threading::Thread::MemoryBarrier();
			//Output->Dispose();
			returnValue = -1;
		}
		NorxCore32::_burn(tempTag->GetBuffer());
		kt = nullptr;
		return returnValue;
	}

	// 64 BIT PUBLIC METHODS =====================================================================================================================================================
	int NorxManaged::Norx64::EncryptStream(
		MemoryStream^ Header,
		MemoryStream^ Message,
		MemoryStream^ Trailer,
		array<const Byte>^ Key,
		array<const Byte>^ Nonce,
		const Byte Rounds,
		const Byte Parallelism,
		const short TagBitSize,
		MemoryStream^ Output)
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
		array<const UInt64>^ kt = reinterpret_cast<array<const UInt64>^>(Key); // prevent unneccessary memory copying of the key!
		//array<UInt64>^ kt = gcnew array<UInt64>(NORX64_KEYWORDS);
		//Buffer::BlockCopy(Key, 0, kt, 0, NORX64_KEYBYTES);
		array<UInt64>^ state = gcnew array<UInt64>(NORX64_STATEWORDS);
		NorxManaged::NorxCore64::_init(state, Nonce, kt, Rounds, Parallelism, TagBitSize);
		NorxManaged::NorxCore64::_absorb(state, Header, HEADER_TAG, Rounds);
		//Output = gcnew array<Byte>(Message != nullptr ? Message->Length + NORX64_TAGBYTES : NORX64_TAGBYTES);
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
				NorxCore64::_merge(state, lanes[i], Rounds); // merge back into the main state and destroy the lane
			}
		}
		//else // Infinite parallelism not implemented (p=0)
		//{ }
		NorxManaged::NorxCore64::_absorb(state, Trailer, TRAILER_TAG, Rounds);
		NorxManaged::NorxCore64::_finalize(state, kt, Rounds, TagBitSize, Output);
		kt = nullptr;
		return 0; // OK
	}

	int NorxManaged::Norx64::DecryptVerifyStream(
		MemoryStream^ Header,
		MemoryStream^ Message,
		MemoryStream^ Trailer,
		array<const Byte>^ Key,
		array<const Byte>^ Nonce,
		const Byte Rounds,
		const Byte Parallelism,
		const short TagBitSize,
		MemoryStream^ Output)
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
		if (Message == nullptr || Message->Length == 0)
			throw gcnew ArgumentNullException("Message", "Message cannot be NULL, and must be at least (TagBitSize / 8) in length.");
		array<const UInt64>^ kt = reinterpret_cast<array<const UInt64>^>(Key); // prevent unneccessary memory copying of the key!
		//array<UInt64>^ kt = gcnew array<UInt64>(NORX64_KEYWORDS);
		//Buffer::BlockCopy(Key, 0, kt, 0, NORX64_KEYBYTES);
		array<UInt64>^ state = gcnew array<UInt64>(NORX64_STATEWORDS);
		NorxManaged::NorxCore64::_init(state, Nonce, kt, Rounds, Parallelism, TagBitSize);
		NorxManaged::NorxCore64::_absorb(state, Header, HEADER_TAG, Rounds);
		//Output = nullptr;
		//if (Message != nullptr)
		//	Output = Message->Length >= NORX64_TAGBYTES ? gcnew array<Byte>(Message->Length - NORX64_TAGBYTES) : nullptr;
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
				NorxCore64::_merge(state, lanes[i], Rounds); // merge back into the main state and destroy the lane
			}
		}
		//else // Infinite parallelism not implemented (p=0)
		//{ }
		NorxManaged::NorxCore64::_absorb(state, Trailer, TRAILER_TAG, Rounds);
		MemoryStream^ temptag = gcnew MemoryStream(TagBitSize / 8);
		array<Byte>^ inputTag = gcnew array<Byte>(TagBitSize / 8);
		Message->Write(inputTag, 0, inputTag->Length);
		NorxManaged::NorxCore64::_finalize(state, kt, Rounds, TagBitSize, temptag);
		int returnValue = -1;
		if (NorxManaged::NorxCore64::norx_verify_tag(inputTag, temptag->GetBuffer()) == 0)
			returnValue = 0; // OK
		else
		{
			NorxCore64::_burn(Output->GetBuffer());
			Output->Flush();
			Threading::Thread::MemoryBarrier();
			//Output->Dispose();
			returnValue = -1;
		}
		NorxCore64::_burn(temptag->GetBuffer());
		kt = nullptr;
		return returnValue;
	}

	int NorxManaged::Norx64::EncryptStream_Detached(
		MemoryStream^ Header,
		MemoryStream^ Message,
		MemoryStream^ Trailer,
		array<const Byte>^ Key,
		array<const Byte>^ Nonce,
		const Byte Rounds,
		const Byte Parallelism,
		const short TagBitSize,
		MemoryStream^ Output,
		MemoryStream^ Tag)
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
		//Tag = gcnew array<Byte>(NORX64_TAGBYTES);
		//Output = Message != nullptr ? gcnew array<Byte>( Message->Length) : nullptr;
		array<const UInt64>^ kt = reinterpret_cast<array<const UInt64>^>(Key); // prevent unneccessary memory copying of the key!
		//array<UInt64>^ kt = gcnew array<UInt64>(NORX64_KEYWORDS);
		//Buffer::BlockCopy(Key, 0, kt, 0, NORX64_KEYBYTES);
		array<UInt64>^ state = gcnew array<UInt64>(NORX64_STATEWORDS);
		NorxManaged::NorxCore64::_init(state, Nonce, kt, Rounds, Parallelism, TagBitSize);
		NorxManaged::NorxCore64::_absorb(state, Header, HEADER_TAG, Rounds);
		//if (Message != nullptr)
		//	Output = gcnew array<Byte>(Message->Length);
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
				NorxCore64::_merge(state, lanes[i], Rounds); // merge back into the main state and destroy the lane
			}
		}
		//else // Infinite parallelism not implemented (p=0)
		//{ }
		NorxManaged::NorxCore64::_absorb(state, Trailer, TRAILER_TAG, Rounds);
		NorxManaged::NorxCore64::_finalize(state, kt, Rounds, TagBitSize, Tag);
		kt = nullptr;
		return 0; // OK
	}

	int NorxManaged::Norx64::DecryptVerifyStream_Detached(
		MemoryStream^ Header,
		MemoryStream^ Message,
		MemoryStream^ Trailer,
		array<const Byte>^ Key,
		array<const Byte>^ Nonce,
		const Byte Rounds,
		const Byte Parallelism,
		array<const Byte>^ Tag,
		MemoryStream^ Output)
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
		array<const UInt64>^ kt = reinterpret_cast<array<const UInt64>^>(Key); // prevent unneccessary memory copying of the key!
		//array<UInt64>^ kt = gcnew array<UInt64>(NORX64_KEYWORDS);
		//Buffer::BlockCopy(Key, 0, kt, 0, NORX64_KEYBYTES);
		array<UInt64>^ state = gcnew array<UInt64>(NORX64_STATEWORDS);
		NorxManaged::NorxCore64::_init(state, Nonce, kt, Rounds, Parallelism, Tag->Length * 8);
		NorxManaged::NorxCore64::_absorb(state, Header, HEADER_TAG, Rounds);
		//Output = nullptr;
		//if (Message != nullptr)
		//	Output = gcnew array<Byte>(Message->Length);

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
				NorxCore64::_merge(state, lanes[i], Rounds); // merge back into the main state and destroy the lane
			}
		}
		//else // Infinite parallelism not implemented (p=0)
		//{ }
		NorxManaged::NorxCore64::_absorb(state, Trailer, TRAILER_TAG, Rounds);
		MemoryStream^ tempTag = gcnew MemoryStream(Tag->Length);
		NorxManaged::NorxCore64::_finalize(state, kt, Rounds, Tag->Length * 8, tempTag);
		int returnValue = -1;
		if (NorxManaged::NorxCore64::norx_verify_tag((array<Byte>^)Tag, tempTag->GetBuffer()) == 0)
			returnValue = 0; // ok
		else
		{
			NorxCore64::_burn(Output->GetBuffer());
			Output->Flush();
			Threading::Thread::MemoryBarrier();
			//Output->Dispose();
			returnValue -1;
		}
		NorxCore64::_burn(tempTag->GetBuffer());
		kt = nullptr;
		return returnValue;
	}
}