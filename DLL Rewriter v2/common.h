#pragma once

#include <map>
#include <memory>
#include <string>

typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned long long ull;
typedef long long ll;

// Round down to the closest value divisible by `mod`
template<typename T1, typename T2> auto align_down(T1 val, T2 mod) -> decltype(T1() + T2())
{
	return val - val % mod;
}

// Round up to the closest value divisible by `mod`
template<typename T1, typename T2> auto align_up(T1 val, T2 mod) -> decltype(T1() + T2())
{
	return val + (mod - val % mod) % mod;
}

void fatal_error(const char* fmt, ...);
std::string read_whole_file(const std::string& path);
std::string read_whole_file(const std::wstring& path);

template<typename ...Args>
std::string format(const std::string& format, Args ...args)
{
	auto size = snprintf(nullptr, 0, format.c_str(), args...) + 1; // +1: Space for '\0'
	std::unique_ptr<char[]> buf(new char[size]);
	snprintf(buf.get(), size, format.c_str(), args...);
	return string(buf.get(), buf.get() + size - 1); // -1 removes '\0'
}

std::map<std::string, uint> parse_map_file(std::string map_file_path);
std::map<std::string, uint> parse_map_file(std::wstring map_file_path);
