/*
* Modified from NORX reference source code package - reference C implementations
*
* Written 2014-2016 by:
*
*      - Samuel Neves <sneves@dei.uc.pt>
*      - Philipp Jovanovic <philipp@jovanovic.io>
*
* Modified 2017 by:
*      - Dustin Sparks <sparkdustjoe@gmail.com>
* 
* To the extent possible under law, the author(s) have dedicated all copyright
* and related and neighboring rights to this software to the public domain
* worldwide. This software is distributed without any warranty.
*
* You should have received a copy of the CC0 Public Domain Dedication along with
* this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#pragma once
#ifndef NORX_NORX_H
#define NORX_NORX_H
#include <stddef.h>
#include <stdint.h>

using namespace System;
using namespace System::Runtime::InteropServices;

namespace NorxManaged 
{
	typedef enum _domain_separator : Byte
	{
		HEADER_TAG = 0x01,
		PAYLOAD_TAG = 0x02,
		TRAILER_TAG = 0x04,
		FINAL_TAG = 0x08,
		BRANCH_TAG = 0x10,
		MERGE_TAG = 0x20
	} _domain_separator;

	public ref class Norx64
	{
	public:		
		static array<Byte>^ EncryptWithTag(
			array<const Byte>^ Header,
			array<const Byte>^ Message,
			array<const Byte>^ Footer,
			array<const Byte>^ Key,
			array<const Byte>^ Nonce,
			const Byte Rounds,
			const Byte Parallelism,
			const short TagBitSize,
			[Out] array<Byte>^% output_tag);
		static array<Byte>^ DecryptAndVerifyTag(
			array<const Byte>^ Header,
			array<const Byte>^ Message,
			array<const Byte>^ Footer,
			array<const Byte>^ Key,
			array<const Byte>^ Nonce,
			const Byte Rounds,
			const Byte Parallelism,
			array<const Byte>^ tag);
	};

	public ref class Norx32
	{
	public:
		static array<Byte>^ EncryptWithTag(
			array<const Byte>^ Header,
			array<const Byte>^ Message,
			array<const Byte>^ Footer,
			array<const Byte>^ Key,
			array<const Byte>^ Nonce,
			const Byte Rounds,
			const Byte Parallelism,
			const short TagBitSize,
			[Out] array<Byte>^% output_tag);
		static array<Byte>^ DecryptAndVerifyTag(
			array<const Byte>^ Header,
			array<const Byte>^ Message,
			array<const Byte>^ Footer,
			array<const Byte>^ Key,
			array<const Byte>^ Nonce,
			const Byte Rounds,
			const Byte Parallelism,
			array<const Byte>^ tag);
	};
}

//#include "norx_config.h"

#endif // NORX_NORX_H