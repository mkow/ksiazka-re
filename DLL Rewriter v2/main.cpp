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
	// Znajdź wolne RVA dla nowej sekcji
	auto free_rva = dll.NextFreeRVA();

	// Wczytaj kod asemblera
	string users_source = read_whole_file(asm_path);

	// Przetwórz tablicę eksportów
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
		// Załaduj strukturę IMAGE_EXPORT_DIRECTORY z danych w pamięci
		auto rva = RVA{ exports_dir_entry.VirtualAddress };
		auto section = dll.SectionFromRVA(rva);
		auto size = sizeof(export_directory);
		if (section.SizeOfRawData - (rva.val - section.VirtualAddress) < size)
		{
			// Tabela eksportów przekracza granicę sekcji lub danych
			// załadowanych z pliku, dla uproszczenia pomijamy ten przypadek
			fatal_error("Unsupported export table location");
		}
		auto export_table_ptr = dll.ConvertTo<PTR>(rva).val;
		memcpy(&export_directory, export_table_ptr, size);
	}

	// Znajdź listę adresów eksportowanych symboli
	auto exported_functions = (uint*)dll.ConvertTo<PTR>(RVA{ export_directory.AddressOfFunctions }).val;

	// Wygeneruj kod asemblera zawierający wrappery na eksportowane
	// funkcje
	string generated_prefix = "__tmp_generated";
	ofstream gen_file(generated_prefix + ".asm", ios::binary);
	gen_file << "[bits 32]\n";
	gen_file << format("[org 0%08xh]\n", free_rva);
	gen_file << "[map symbols " << generated_prefix << ".map]\n";
	gen_file << users_source;
	gen_file << "\n";

	// Dla każdej funkcji wygeneruj wywołanie makra 'redirect'
	// z odpowiednimi parametrami (jej adres oraz indeks)
	for (DWORD i = 0; i < export_directory.NumberOfFunctions; i++)
	{
		auto func_addr = RVA{ exported_functions[i] };
		if (dll.IsAddrExecutable(func_addr) && !is_export_forwarded(exports_dir_entry, func_addr))
			gen_file << format("redirect 0%08xh, %d\n", func_addr, i);
	}
	gen_file.close();

	// Skompiluj wygenerowany kod przy użyciu asemblera nasm
	auto command = format(R"(nasm "%s.asm" -O0 -o "%s.bin")",
	                      generated_prefix.c_str(),
						  generated_prefix.c_str());
	// Używanie funkcji system() nie jest zalecane, jednak inne metody
	// niepotrzebnie skomplikowałyby kod
	system(command.c_str());

	// Przygotuj nową sekcję i umieść w niej skompilowany kod asemblera
	string compiled = read_whole_file(generated_prefix + ".bin");
	dll.AddSection("wrappers",
	               free_rva,
				   align_up(compiled.size(), dll.OptionalHeader().SectionAlignment),
				   compiled,
				   IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE);

	// Zmień adresy funkcji w tabeli eksportów, tak by wskazywały teraz
	// na wygenerowane przez nas wstawki
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
