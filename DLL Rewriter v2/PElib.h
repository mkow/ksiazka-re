/*
This library provides `PE` class which allows simple operations on 32-bit PE files.
*/

#pragma once

#include <map>
#include <string>
#include <vector>

#include <Windows.h>

#include "common.h"

// Typy adresów:
enum class ADDR_TYPE { RVA, VA, FILE_OFFSET, PTR };

namespace PElib
{

struct RVA { uint val; };  // Relative Virtual Address
struct VA { uint val; };   // Virtual address (RVA + OptionalHeader.ImageBase)
struct FILE_OFFSET { uint val; }; // File offset
struct PTR { char* val; }; // Pointer to section data loaded to memory by PE class

class PE
{
	bool sections_loaded;
	char* stub;
	uint dos_stub_size;
	IMAGE_DOS_HEADER MZ_header;
	IMAGE_NT_HEADERS PE_header;
	std::vector<IMAGE_SECTION_HEADER> sections_hdrs;
	std::vector<char*> sections_data;

	void Load(const std::wstring& path);
	void Load(const void* pe_data);
	void CommonInit();

	static uint Checksum(const std::string& mem);

public:
	PE();
	PE(const void* data);
	PE(const wchar_t* file_path);
	PE(const std::wstring& file_path);
	virtual ~PE();

	void AddSection(const std::string& name, RVA rva, uint vsize,
					const std::string& data, DWORD characteristics);
	void RemoveSection(int index);
	RVA NextFreeRVA() const;
	const IMAGE_SECTION_HEADER& SectionFromRVA(RVA rva) const;
	const IMAGE_DATA_DIRECTORY& Directory(uint index) const;
	const IMAGE_DOS_HEADER& MzHeader() const;
	const IMAGE_NT_HEADERS& PeHeader() const;
	const IMAGE_FILE_HEADER& FileHeader() const;
	const IMAGE_OPTIONAL_HEADER& OptionalHeader() const;
	bool IsAddrReadable(RVA rva) const;
	bool IsAddrWritable(RVA rva) const;
	bool IsAddrExecutable(RVA rva) const;
	void Save(const std::wstring& file_path);

	template<typename TO, typename FROM>
	TO ConvertTo(FROM from);
};

// Partial specialization is not allowed for functions/methods (no idea why), so we can't easily
// do this for all <T, T>.
template<> inline RVA PE::ConvertTo<RVA, RVA>(RVA from)
{
	return from;
}

//--------------------------------------------------------
// * -> RVA converters
//--------------------------------------------------------
template<> inline RVA PE::ConvertTo<RVA, VA>(VA from)
{
	if (from.val < PE_header.OptionalHeader.ImageBase
		|| from.val >= PE_header.OptionalHeader.ImageBase + PE_header.OptionalHeader.SizeOfImage)
		fatal_error("Invalid argument passed to " __FUNCTION__ "! VA=%08x)", from);
	return RVA{ from.val - PE_header.OptionalHeader.ImageBase };
}

template<> inline RVA PE::ConvertTo<RVA, FILE_OFFSET>(FILE_OFFSET from)
{
	for (const auto& hdr : sections_hdrs)
		if (hdr.PointerToRawData <= from.val
			&& from.val < hdr.PointerToRawData + hdr.SizeOfRawData)
		{
			return RVA{ from.val + hdr.VirtualAddress - hdr.PointerToRawData };
		}
	fatal_error("Bad argument passed to " __FUNCTION__ "! (FILE_OFFSET=%08x)", from.val);
}

template<> inline RVA PE::ConvertTo<RVA, PTR>(PTR from)
{
	for (int i = 0; i < sections_data.size(); i++)
		if (sections_data[i] <= from.val
			&& from.val < sections_data[i] + sections_hdrs[i].SizeOfRawData)
		{
			return RVA{ from.val - sections_data[i] + sections_hdrs[i].VirtualAddress };
		}
	fatal_error("Bad argument passed to " __FUNCTION__ "! (PTR=%08x)", from.val);
}

//--------------------------------------------------------
// RVA -> * converters
//--------------------------------------------------------

template<> inline VA PE::ConvertTo<VA, RVA>(RVA from)
{
	if (from.val >= PE_header.OptionalHeader.SizeOfImage)
		fatal_error("Invalid argument passed to " __FUNCTION__ "! RVA=%08x)", from);
	return VA{ from.val + PE_header.OptionalHeader.ImageBase };
}

template<> inline FILE_OFFSET PE::ConvertTo<FILE_OFFSET, RVA>(RVA from)
{
	for (const auto& hdr : sections_hdrs)
		if (hdr.VirtualAddress <= from.val
			&& from.val < hdr.VirtualAddress + hdr.Misc.VirtualSize)
		{
			return FILE_OFFSET{ from.val - hdr.VirtualAddress + hdr.PointerToRawData };
		}
	fatal_error("Bad argument passed to " __FUNCTION__ "! (RVA=%08x)", from.val);
}

template<> inline PTR PE::ConvertTo<PTR, RVA>(RVA from)
{
	for (int i = 0; i < sections_hdrs.size(); i++)
		if (sections_hdrs[i].VirtualAddress <= from.val
			&& from.val < sections_hdrs[i].VirtualAddress + sections_hdrs[i].Misc.VirtualSize)
		{
			return PTR{ sections_data[i] + (from.val - sections_hdrs[i].VirtualAddress) };
		}
	fatal_error("Bad argument passed to " __FUNCTION__ "! (RVA=%08x)", from.val);
}

// `FROM` -> RVA -> `TO`
template<typename TO, typename FROM> TO PE::ConvertTo(FROM from)
{
	return PE::ConvertTo<TO>(PE::ConvertTo<RVA>(from));
}

}
