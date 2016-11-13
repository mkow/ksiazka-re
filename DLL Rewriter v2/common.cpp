#include "common.h"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <map>
#include <sstream>
#include <string>

#include <conio.h> // for _getch()
#include <Windows.h>

#ifdef max // garbage from Windows.h
#undef max
#endif

using std::hex;
using std::ifstream;
using std::ios;
using std::map;
using std::numeric_limits;
using std::string;
using std::wstring;

[[noreturn]] void fatal_error(const char* fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	fprintf(stderr, "Error: ");
	vfprintf(stderr, fmt, va);
	fprintf(stderr, "\n");
	va_end(va);

#if defined(_MSC_VER) && defined(_DEBUG)
	puts("[Press any key]");
	_getch();
#endif

	exit(1);
}

string read_whole_file(const string& path)
{
	return read_whole_file(wstring(path.begin(), path.end()));
}

string read_whole_file(const wstring& path)
{
	ifstream file(path, ios::binary);
	if (file.fail())
		fatal_error("Cannot open file: %ls", path.c_str());
	file.seekg(0, ios::end);
	auto size = file.tellg();
	file.seekg(0);

	string buffer;
	if (size > numeric_limits<size_t>::max())
		// We have to check this, otherwise buffer.resize() would trim
		// the value, but file.read wouldn't.
		fatal_error("File too big to load to memory: %ls", path.c_str());
	buffer.resize((size_t)size);
	file.read(&buffer[0], size);
	if (file.fail())
		fatal_error("Cannot read file: %ls", path.c_str());
	return buffer;
}

map<string, uint> parse_map_file(string map_file_path)
{
	return parse_map_file(wstring(map_file_path.begin(), map_file_path.end()));
}

map<string, uint> parse_map_file(wstring map_file_path)
{
	map<string, uint> res;
	ifstream file(map_file_path);
	bool after_marker = false;

	string line;
	while (std::getline(file, line))
	{
		if (line.find("__begin_marker") != string::npos)
			after_marker = true;
		if (after_marker)
		{
			// Parse current line.
			// Format example: "           FA000             FA000  longjmp_0"
			std::stringstream stream(line);
			uint unused;
			uint rva;
			string label;
			stream >> hex >> unused;
			stream >> hex >> rva;
			stream >> hex >> label;
			if (!label.empty())
				res[label] = rva;
		}
	}

	return res;
}
