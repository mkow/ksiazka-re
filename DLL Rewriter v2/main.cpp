#include <cstdio>
#include <fstream>

#include <Windows.h>

#include "PElib.h"
#include "common.h"

using std::ios;
using std::map;
using std::ofstream;
using std::string;
using std::wstring;

using PElib::PE;
using PElib::RVA;
using PElib::VA;
using PElib::FILE_OFFSET;
using PElib::PTR;

using namespace std::string_literals;

bool is_export_forwarded(const IMAGE_DATA_DIRECTORY& exports_dir, RVA exported_rva)
{
	return exports_dir.VirtualAddress <= exported_rva.val
		&& exported_rva.val < exports_dir.VirtualAddress + exports_dir.Size;
}

int wmain(int argc, const wchar_t* argv[])
{
	if (argc < 2)
		fatal_error("Please specify DLL path in argv[1]");
	if (argc < 3)
		fatal_error("Please specify a path to redirection code in argv[2]");

	PE dll(argv[1]);
	wstring asm_path = argv[2];
	// Find free RVA for new section
	auto free_rva = dll.NextFreeRVA();

	// Load assembly code
	string users_source = read_whole_file(asm_path);

	// Parse export table
	const auto& exports_dir_entry = dll.Directory(IMAGE_DIRECTORY_ENTRY_EXPORT);
	IMAGE_EXPORT_DIRECTORY export_directory;

	if (!exports_dir_entry.VirtualAddress || !exports_dir_entry.Size)
	{
		fatal_error("This DLL doesn't have an export table, nothing to do.");
	}
	else if (exports_dir_entry.Size < sizeof(IMAGE_EXPORT_DIRECTORY))
	{
		fatal_error("Invalid export table size!");
	}
	else
	{
		// Load IMAGE_EXPORT_DIRECTORY struct from in-memory file data
		auto rva = RVA{ exports_dir_entry.VirtualAddress };
		auto section = dll.SectionFromRVA(rva);
		auto size = sizeof(export_directory);
		if (section.SizeOfRawData - (rva.val - section.VirtualAddress) < size)
		{
			// Export table crosses section boundary or file data,
			// we're skipping this case for simplicity.
			fatal_error("Unsupported export table location");
		}
		auto export_table_ptr = dll.ConvertTo<PTR>(rva).val;
		memcpy(&export_directory, export_table_ptr, size);
	}

	// Find array with addresses of exported symbols
	auto exported_functions = (uint*)dll.ConvertTo<PTR>(RVA{ export_directory.AddressOfFunctions }).val;

	// Generate assembly code containing wrappers for exported functions
	string generated_prefix = "__tmp_generated";
	ofstream gen_file(generated_prefix + ".asm", ios::binary);
	gen_file << "[bits 32]\n";
	gen_file << format("[org 0%08xh]\n", free_rva);
	gen_file << "[map symbols " << generated_prefix << ".map]\n";
	gen_file << users_source;
	gen_file << "\n";

	// Generate `redirect` macro call for every exported function,
	// passing function address and index as arguments.
	for (DWORD i = 0; i < export_directory.NumberOfFunctions; i++)
	{
		auto func_addr = RVA{ exported_functions[i] };
		if (dll.IsAddrExecutable(func_addr) && !is_export_forwarded(exports_dir_entry, func_addr))
			gen_file << format("redirect 0%08xh, %d\n", func_addr, i);
	}
	gen_file.close();

	// Compile generated code using nasm
	auto command = format(R"(nasm "%s.asm" -O0 -o "%s.bin")",
	                      generated_prefix.c_str(),
						  generated_prefix.c_str());
	// Using system() is generally a bad thing, but it's the simplest solution here.
	system(command.c_str());

	// Prepare new section and place compiled assembly in it.
	string compiled = read_whole_file(generated_prefix + ".bin");
	dll.AddSection("wrappers",
	               free_rva,
				   align_up(compiled.size(), dll.OptionalHeader().SectionAlignment),
				   compiled,
				   IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE);

	// Change function pointers in export table so they point to generated wrappers.
	map<string, uint> labels = parse_map_file(generated_prefix + ".map");
	for (int i = 0; i < export_directory.NumberOfFunctions; i++)
	{
		auto func_addr = RVA{ exported_functions[i] };
		if (dll.IsAddrExecutable(func_addr) && !is_export_forwarded(exports_dir_entry, func_addr))
			exported_functions[i] = labels[format("entry_%d", i)];
	}

	dll.Save(argv[1] + L".rebuilt.dll"s);
	puts("Done!");
	return 0;
}
