#pragma once
#include <string>
#include <windows.h>
#include <detours.h>
#include <iostream>
std::string  full_path, path, file_name;
std::wstring w_full_path, w_path, w_file_name;
std::string mon_func_name;
FARPROC cur_mon_func;
LPVOID cur_data;
bool flag_hidden_flag = false;

std::string getPathFromFullPath(std::string&& fullpath_)
{
    size_t pos_slash = fullpath_.rfind('\\');
    std::string path = fullpath_.substr(0, pos_slash + 1);

    return path;
}

std::wstring wgetPathFromFullPath(std::wstring&& wfullpath_)
{
    size_t pos_slash = wfullpath_.rfind('\\');
    std::wstring w_path = wfullpath_.substr(0, pos_slash + 1);

    return w_path;
}

HANDLE(WINAPI* pCreateFileA) (LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileA;
HANDLE(WINAPI* pCreateFileW) (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileW;
HANDLE(WINAPI* pFindFirstFileW) (LPCWSTR lpFileName, LPWIN32_FIND_DATA lpFindFileData) = FindFirstFileW;
HANDLE(WINAPI* pFindFirstFileA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) = FindFirstFileA;
BOOL(WINAPI* pFindNextFileW) (HANDLE hFindFile, LPWIN32_FIND_DATA lpFindFileData) = FindNextFileW;
BOOL(WINAPI* pFindNextFileA) (HANDLE hFindFile, LPWIN32_FIND_DATAA  lpFindFileData) = FindNextFileA;
HANDLE(WINAPI* pFindFirstFileExA) (LPCSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS  fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags) = FindFirstFileExA;
HANDLE(WINAPI* pFindFirstFileExW) (LPCWSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS  fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags) = FindFirstFileExW;

HANDLE WINAPI MyCreateFileA_withHide(
	LPCSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile)
{
	//std::cout << "CreateFileA: " << lpFileName << full_path << std::endl;
	if (lpFileName == full_path) {
		return INVALID_HANDLE_VALUE;
	}
	return pCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE WINAPI MyCreateFileW_withHide(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile)
{
	//std::wcout << "CreateFileW: " << lpFileName << w_full_path << std::endl;
	if (lpFileName == w_full_path) {
		return INVALID_HANDLE_VALUE;
	}
	return pCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE WINAPI MyFindFirstFileA_withHide(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
{
	//std::cout << "FindFirstFileA: " << lpFileName << full_path << std::endl;
	if (lpFileName == full_path) {
		return INVALID_HANDLE_VALUE;
	}
	return pFindFirstFileA(lpFileName, lpFindFileData);
}

HANDLE WINAPI MyFindFirstFileW_withHide(LPCWSTR lpFileName, LPWIN32_FIND_DATA lpFindFileData)
{
	//std::wcout << "FindFirstFileW: " << lpFileName << w_full_path << std::endl;
	if (lpFileName == w_full_path) {
		return INVALID_HANDLE_VALUE;
	}
	return pFindFirstFileW(lpFileName, lpFindFileData);
}

BOOL WINAPI MyFindNextFileA_withHide(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
{
	std::cout << "FindNextFileA: " << lpFindFileData->cFileName << full_path << std::endl;
	bool ret = pFindNextFileA(hFindFile, lpFindFileData);
	if (lpFindFileData->cFileName == full_path) {
		ret = pFindNextFileA(hFindFile, lpFindFileData);
	}
	return ret;
}

BOOL WINAPI MyFindNextFileW_withHide(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData)
{
	//std::wcout << "FindNextFileW: " << lpFindFileData->cFileName << w_full_path << std::endl;
	bool ret = pFindNextFileW(hFindFile, lpFindFileData);
	if (lpFindFileData->cFileName == w_full_path) {
		ret = pFindNextFileW(hFindFile, lpFindFileData);
	}
	return ret;
}

HANDLE MyFindFirstFileExW_withHide(
	LPCWSTR a0,
	FINDEX_INFO_LEVELS a1,
	LPWIN32_FIND_DATAW a2,
	FINDEX_SEARCH_OPS a3,
	LPVOID a4,
	DWORD a5)
{
	//std::wcout << "pFindFirstFileExW: " << a2->cFileName << w_full_path << std::endl;
	HANDLE ret = pFindFirstFileExW(a0, a1, a2, a3, a4, a5);
	if (a2->cFileName == w_full_path)
	{
		 //pFindNextFileW(ret, a2);
		ret = INVALID_HANDLE_VALUE;
	}
	return ret;
}

HANDLE MyFindFirstFileExA_withHide(
	LPCSTR a0,
	FINDEX_INFO_LEVELS a1,
	LPWIN32_FIND_DATAA a2,
	FINDEX_SEARCH_OPS a3,
	LPVOID a4,
	DWORD a5)
{
	//std::cout << "pFindFirstFileExA: " << a2->cFileName << full_path << std::endl;
	HANDLE ret = pFindFirstFileExA(a0, a1, a2, a3, a4, a5);
	if (a2->cFileName == full_path)
	{
		ret = INVALID_HANDLE_VALUE;
	}
	return ret;
}

void setPathsToFile(std::string& fileName_)
{
    size_t pos_slash = fileName_.rfind('\\');

    full_path = fileName_;
    path = full_path.substr(0, pos_slash + 1);
    file_name = full_path.substr(pos_slash + 1, full_path.length());

    w_full_path = std::wstring(full_path.begin(), full_path.end());
    w_path = std::wstring(path.begin(), path.end());
    w_file_name = std::wstring(file_name.begin(), file_name.end());
}

int HideFile(std::string& fileName)
{


	size_t pos_slash = fileName.rfind('\\');

	full_path = fileName;
	path = full_path.substr(0, pos_slash + 1);
	file_name = full_path.substr(pos_slash + 1, full_path.length());

	w_full_path = std::wstring(full_path.begin(), full_path.end());
	w_path = std::wstring(path.begin(), path.end());
	w_file_name = std::wstring(file_name.begin(), file_name.end());


	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pCreateFileA, MyCreateFileA_withHide);
	LONG err = DetourTransactionCommit();
	if (err != NO_ERROR)
		return -1;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pCreateFileW, MyCreateFileW_withHide);
	 err = DetourTransactionCommit();
	if (err != NO_ERROR)
		return -1;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pFindFirstFileW, MyFindFirstFileW_withHide);
	 err = DetourTransactionCommit();
	if (err != NO_ERROR)
		return -1;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pFindFirstFileA, MyFindFirstFileA_withHide);
	err = DetourTransactionCommit();
	if (err != NO_ERROR)
		return -1;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pFindNextFileW, MyFindNextFileW_withHide);
	 err = DetourTransactionCommit();
	if (err != NO_ERROR)
		return -1;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pFindNextFileA, MyFindNextFileA_withHide);
	 err = DetourTransactionCommit();
	if (err != NO_ERROR)
		return -1;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pFindFirstFileExW, MyFindFirstFileExW_withHide);
	 err = DetourTransactionCommit();
	if (err != NO_ERROR)
		return -1;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pFindFirstFileExA, MyFindFirstFileExA_withHide);
	err = DetourTransactionCommit();
	if (err != NO_ERROR)
		return -1;

    return 0;
}