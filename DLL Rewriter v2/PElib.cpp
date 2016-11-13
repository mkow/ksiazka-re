#include "PElib.h"

#include <fstream>
#include <limits>

#include "common.h"

#ifdef max // garbage from Windows.h
#undef max
#endif

using std::ios;
using std::numeric_limits;
using std::map;
using std::ifstream;
using std::ofstream;
using std::string;
using std::wstring;
using std::vector;

namespace PElib
{

uint PE::Checksum(const string& data)
{
	uint res = 0;
	// We don't have to care about odd-length data, because
	// std::string::c_str returns data ending with a '\0'.
	for (string::size_type i = 0; i * 2 < data.size(); i++)
	{
		res += ((const ushort*)data.c_str())[i];
		res = (ushort)res + (res >> 16);
	}
	return res + data.size();
}

PE::PE()
{
	CommonInit();
}

PE::PE(const void* data)
{
	CommonInit();
	Load(data);
}

PE::PE(const wchar_t* file_path)
{
	CommonInit();
	Load(wstring(file_path));
}

PE::PE(const wstring& file_path)
{
	CommonInit();
	Load(file_path);
}

PE::~PE()
{
	for (size_t i = 0; i < sections_data.size(); i++)
		delete[] sections_data[i];
}

void PE::CommonInit()
{
	sections_loaded = false;
	dos_stub_size = 0;
	stub = nullptr;
	memset(&MZ_header, 0, sizeof(MZ_header));
	memset(&PE_header, 0, sizeof(PE_header));
}

void PE::Load(const wstring& fname)
{
	string data = read_whole_file(fname);
	Load(data.c_str());
}

void PE::Load(const void* pe_data)
{
	const char* mem_begin = (const char*)pe_data;
	const char* mem_it = mem_begin;

	// MZ header
	memcpy(&MZ_header, mem_it, sizeof(MZ_header));
	// Load DOS stub, verifying that it fits between MZ header end and data pointed by e_lfanew
	if (MZ_header.e_lfanew - sizeof(MZ_header) > 0)
	{
		dos_stub_size = MZ_header.e_lfanew - sizeof(MZ_header);
		stub = new char[dos_stub_size];
		memcpy(stub, mem_it + sizeof(MZ_header), dos_stub_size);
	}
	mem_it += MZ_header.e_lfanew;

	// PE header
	auto header_size = sizeof(PE_header.Signature) + sizeof(PE_header.FileHeader);
	memcpy(&PE_header, mem_it, header_size);
	memcpy(&PE_header.OptionalHeader,
		   mem_it + header_size,
		   PE_header.FileHeader.SizeOfOptionalHeader);
	mem_it += header_size + PE_header.FileHeader.SizeOfOptionalHeader;

	// Section headers
	if (PE_header.OptionalHeader.NumberOfRvaAndSizes > IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
		fatal_error("Bad value of field PE.OptionalHeader.NumberOfRvaAndSizes: %d",
					PE_header.OptionalHeader.NumberOfRvaAndSizes);
	for (int i = 0; i < PE_header.FileHeader.NumberOfSections; i++)
	{
		sections_hdrs.push_back(*(IMAGE_SECTION_HEADER*)mem_it);
		char* ptr = new char[sections_hdrs.back().SizeOfRawData];
		memcpy(ptr,
			   mem_begin + sections_hdrs.back().PointerToRawData,
			   sections_hdrs.back().SizeOfRawData);
		sections_data.push_back(ptr);
		mem_it += sizeof(sections_hdrs[0]);
	}
	sections_loaded = true;
}

void PE::AddSection(const string& name, RVA rva, uint vsize, const string& data,
					DWORD characteristics)
{
	IMAGE_SECTION_HEADER hdr;
	memset(&hdr, 0, sizeof(hdr));
	memcpy(hdr.Name, name.c_str(), min(sizeof(hdr.Name), name.size()));
	hdr.Characteristics = characteristics;
	hdr.VirtualAddress = rva.val;
	hdr.Misc.VirtualSize = vsize;
	hdr.SizeOfRawData = data.size();
	sections_hdrs.push_back(hdr);

	char* buf = new char[data.size()];
	memcpy(buf, data.c_str(), data.size());
	sections_data.push_back(buf);
	PE_header.FileHeader.NumberOfSections++;
}

void PE::RemoveSection(int index)
{
	sections_hdrs.erase(sections_hdrs.begin() + index);
	sections_data.erase(sections_data.begin() + index);
	PE_header.FileHeader.NumberOfSections--;
}

RVA PE::NextFreeRVA() const
{
	return RVA{ sections_hdrs.back().VirtualAddress +
		align_up(sections_hdrs.back().Misc.VirtualSize,
				 PE_header.OptionalHeader.SectionAlignment) };
}

const IMAGE_SECTION_HEADER& PE::SectionFromRVA(RVA rva) const
{
	for (auto& header : sections_hdrs)
		if (header.VirtualAddress <= rva.val
			&& rva.val < header.VirtualAddress + header.Misc.VirtualSize)
		{
			return header;
		}
	fatal_error("Bad argument passed to " __FUNCTION__ "! (RVA=%08x)", rva);
}

const IMAGE_DATA_DIRECTORY& PE::Directory(uint index) const
{
	if (index >= PE_header.OptionalHeader.NumberOfRvaAndSizes)
		fatal_error("Bad argument passed to " __FUNCTION__ "! (index=%08x)", index);
	return PE_header.OptionalHeader.DataDirectory[index];
}

const IMAGE_DOS_HEADER& PE::MzHeader() const
{
	return MZ_header;
}

const IMAGE_NT_HEADERS& PE::PeHeader() const
{
	return PE_header;
}

const IMAGE_FILE_HEADER& PE::FileHeader() const
{
	return PE_header.FileHeader;
}

const IMAGE_OPTIONAL_HEADER& PE::OptionalHeader() const
{
	return PE_header.OptionalHeader;
}

bool PE::IsAddrReadable(RVA rva) const
{
	const auto& section = SectionFromRVA(rva);
	return (section.Characteristics & IMAGE_SCN_MEM_READ) != 0;
}

bool PE::IsAddrWritable(RVA rva) const
{
	const auto& section = SectionFromRVA(rva);
	return (section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
}

bool PE::IsAddrExecutable(RVA rva) const
{
	const auto& section = SectionFromRVA(rva);
	return (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
}

void PE::Save(const std::wstring& file_path)
{
	// Fix pointers
	MZ_header.e_lfanew = sizeof(MZ_header) + dos_stub_size;
	if (sections_hdrs.size() > numeric_limits<WORD>::max())
		fatal_error("Too many sections! (%zd)", sections_hdrs.size());
	PE_header.FileHeader.NumberOfSections = (WORD)sections_hdrs.size();
	PE_header.FileHeader.SizeOfOptionalHeader = sizeof(PE_header.OptionalHeader);
	PE_header.OptionalHeader.FileAlignment = 0x200;
	PE_header.OptionalHeader.SectionAlignment = 0x1000;
	PE_header.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
	PE_header.OptionalHeader.SizeOfImage =
		align_up(sections_hdrs.back().VirtualAddress + sections_hdrs.back().Misc.VirtualSize,
				 PE_header.OptionalHeader.SectionAlignment);
	PE_header.OptionalHeader.SizeOfHeaders =
		align_up(MZ_header.e_lfanew + sizeof(PE_header.Signature) + sizeof(PE_header.FileHeader)
				 + PE_header.FileHeader.SizeOfOptionalHeader
				 + sections_hdrs.size() * sizeof(sections_hdrs[0]),
				 PE_header.OptionalHeader.FileAlignment);
	uint file_pos = PE_header.OptionalHeader.SizeOfHeaders;
	for (auto& header : sections_hdrs)
	{
		header.PointerToRawData = file_pos;
		file_pos = align_up(file_pos + header.SizeOfRawData,
							PE_header.OptionalHeader.FileAlignment);
	}

	// Build new PE file in memory
	string res;

	res.append({ (const char*)&MZ_header, sizeof(MZ_header) });
	res.append({ (const char*)stub, dos_stub_size });
	auto checksum_pos = res.size()
		+ offsetof(decltype(PE_header), OptionalHeader)
		+ offsetof(decltype(PE_header.OptionalHeader), CheckSum);
	res.append({ (const char*)&PE_header, sizeof(PE_header) });
	for (auto& header : sections_hdrs)
		res.append({ (const char*)&header, sizeof(header) });
	uint pos = res.size();
	char* nullmem = new char[PE_header.OptionalHeader.FileAlignment];
	memset(nullmem, 0, PE_header.OptionalHeader.FileAlignment);
	for (size_t i = 0; i < sections_hdrs.size(); i++)
	{
		auto aligned = align_up(pos, PE_header.OptionalHeader.FileAlignment);
		res.append(nullmem, aligned - pos);
		pos = aligned;
		res.append(sections_data[i], sections_hdrs[i].SizeOfRawData);
		pos += sections_hdrs[i].SizeOfRawData;
	}
	delete[] nullmem;

	// Fix PE checksum
	auto checksum_ptr = &res[checksum_pos];
	memset(checksum_ptr, 0, sizeof(DWORD));
	DWORD new_checksum = Checksum(res);
	memcpy(checksum_ptr, &new_checksum, sizeof(DWORD));

	// Write to file
	ofstream f(file_path, ios::binary);
	if (f.fail())
		fatal_error("Cannot open file: %ls", file_path.c_str());
	f << res;
	f.close();
}

}