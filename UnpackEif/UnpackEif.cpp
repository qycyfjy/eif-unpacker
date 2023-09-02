#include <fstream>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <chrono>

#define NOMINMAX
#include <Windows.h>
#include "CFB.h"

std::string ConvertWideToUTF8(const std::wstring& wstr)
{
	int count = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), wstr.length(), NULL, 0, NULL, NULL);
	std::string str(count, 0);
	WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], count, NULL, NULL);
	return str;
}

std::wstring ConvertANSIToWide(const char* str)
{
	if (!str || strlen(str) == 0)
	{
		return {};
	}
	int count = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
	count -= 1;
	std::wstring wstr(count, 0);
	MultiByteToWideChar(CP_ACP, 0, str, -1, &wstr[0], count);
	return wstr;
}

std::wstring ConvertUTF8ToWide(const std::string& s)
{
	int count = MultiByteToWideChar(CP_UTF8, 0, s.data(), -1, NULL, 0);
	std::wstring wstr;
	wstr.reserve(count);
	MultiByteToWideChar(CP_UTF8, 0, s.data(), -1, &wstr[0], count);
	return wstr;
}

std::string GetUtf8String(const char* str)
{
	return ConvertWideToUTF8(ConvertANSIToWide(str));
}

constexpr const char* kOutDirName = "unpack";
constexpr const char* kOutDir = "unpack/";

int main(int argc, char* argv[])
{
	::SetConsoleOutputCP(CP_UTF8);

	const char* eifFilename = nullptr;

#ifdef _DEBUG
	eifFilename = "tu.eif";
#else
	if (argc < 2) {
		std::cout << "拖到程序图标上解压" << '\n';
		return -1;
	}
	eifFilename = argv[1];
#endif // _DEBUG

	std::ifstream eif(eifFilename, std::ios::binary);
	if (!eif.is_open()) {
		std::cout << "打开失败\n";
		return -1;
	}

	std::cout << "正在读取" << GetUtf8String(eifFilename) << "...\n";

	std::string data{ std::istreambuf_iterator<char>(eif), std::istreambuf_iterator<char>() };

	eif.close();

	std::cout << "正在解压...\n";

	CFB::CompoundFile file;
	file.read(data.data(), data.size());
	std::unordered_map<std::string, const CFB::DirectoryEntry*> entries;
	file.iterateAll([&entries](const CFB::DirectoryEntry* entry, size_t depth)
		{
			if (depth == 1) {
				std::string name = CFB::internal::convertUTF16ToUTF8(entry->name);
				auto pos = name.find_last_of(".");
				if (name[pos - 3] == 'f' && name[pos - 2] == 'i' && name[pos - 1] == 'x') {
					return;
				}
				entries[std::move(name)] = entry;
			}
		});

	if (CreateDirectory(ConvertUTF8ToWide(kOutDir).c_str(), NULL) || ERROR_ALREADY_EXISTS == GetLastError())
	{
		for (auto& [name, entry] : entries) {
			std::string outFilename = kOutDir + name;
			std::ofstream out(ConvertUTF8ToWide(outFilename), std::ios::trunc | std::ios::binary);
			if (!out.is_open()) {
				throw std::runtime_error("failed to write " + outFilename + '\n');
			}
			std::vector<char> bytes = file.readStreamOfEntry(entry);
			out.write(bytes.data(), bytes.size());
			out.flush();
			out.close();
		}
	}

	std::cout << "已解压到unpack文件夹! X掉窗口或者回车." << std::endl;
	(void)getchar();
}

