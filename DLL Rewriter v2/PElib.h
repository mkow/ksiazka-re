#pragma once

#include <map>
#include <string>
#include <vector>

#include <Windows.h>

#include "common.h"

// Typy adresów:
//  RVA: adres względem początku obrazu
//  VA: adres wirtualny (RVA + OptionalHeader.ImageBase)
//  FILE_OFFSET: offset w pliku
//  PTR: wskaźnik na dane w pamięci sekcji załadowanej przez klasę PE
enum class ADDR_TYPE { RVA, VA, FILE_OFFSET, PTR };

class PE
{
private:
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

	void AddSection(const std::string& name, uint rva, uint vsize,
	                const std::string& data, DWORD characteristics);
	void RemoveSection(int index);
	uint NextFreeRVA() const;
	const IMAGE_SECTION_HEADER& SectionFromRVA(uint rva) const;
	const IMAGE_DATA_DIRECTORY& Directory(uint index) const;
	const IMAGE_DOS_HEADER& MzHeader() const;
	const IMAGE_NT_HEADERS& PeHeader() const;
	const IMAGE_FILE_HEADER& FileHeader() const;
	const IMAGE_OPTIONAL_HEADER& OptionalHeader() const;
	bool IsAddrReadable(uint rva) const;
	bool IsAddrWritable(uint rva) const;
	bool IsAddrExecutable(uint rva) const;
	void Save(const std::wstring& file_path);
	void* Convert(void* addr, ADDR_TYPE from, ADDR_TYPE to) const;
};
