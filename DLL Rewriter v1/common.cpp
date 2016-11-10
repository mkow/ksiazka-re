#include "common.h"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <sstream>
#include <string>

#include <conio.h> // potrzebne do _getch()
#include <Windows.h>

using std::hex;
using std::ifstream;
using std::ios;
using std::map;
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
  file.seekg(0, ios::end);
  auto size = file.tellg();
  file.seekg(0);

  string buffer;
  buffer.resize(size);
  file.read(&buffer[0], size);
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
      // Sparsuj aktualną linię
      // Przykład formatu: "           FA000             FA000  longjmp_0"
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
