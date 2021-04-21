#define WIN32_LEAN_AND_MEAN 
#include <winsock2.h> 
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <comdef.h>
#include <vector>
#include <tchar.h>
#include <ShlObj.h>
#define BUFSIZE 512

DWORD WINAPI InstanceThread(LPVOID);
int LoadLibByPID(DWORD processId);


DWORD getPidByName(std::string processname) {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD result = NULL;
    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(0x00000002, 0);
    if (INVALID_HANDLE_VALUE == hProcessSnap) return(FALSE);
    pe32.dwSize = sizeof(PROCESSENTRY32); // <----- IMPORTANT
    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);          // clean the snapshot object
        printf("!!! Failed to gather information on system processes! \n");
        return(NULL);
    }
    do {
        _bstr_t b(pe32.szExeFile);
        const char* c = b;
        if (0 == strcmp(processname.c_str(), c)) {
            result = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));
    CloseHandle(hProcessSnap);
    return result;
}
int LoadLibByPID(DWORD processId) {
    char dllName[BUFSIZE];
    GetModuleFileNameA(NULL, dllName, BUFSIZE);
    size_t len = sizeof(dllName);
    while (dllName[--len] != '\\')
        dllName[len] = 0;
    strncat_s(dllName, "hook.dll",BUFSIZE);
    HANDLE openedProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (openedProcess == NULL) {
        printf("OpenProcess error code: %d\r\n", GetLastError());
        return 0;
    }
    HMODULE kernelModule = GetModuleHandleW(L"kernel32.dll");
    if (kernelModule == NULL) {
        printf("GetModuleHandleW error code: %d\r\n", GetLastError());
        CloseHandle(openedProcess);
        return 0;
    }
    LPVOID loadLibraryAddr = GetProcAddress(kernelModule, "LoadLibraryA");
    if (loadLibraryAddr == NULL) {
        printf("GetProcAddress error code: %d\r\n", GetLastError());
        CloseHandle(openedProcess);
        return 0;
    }
    LPVOID argLoadLibrary = (LPVOID)VirtualAllocEx(openedProcess, NULL, strlen(dllName), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (argLoadLibrary == NULL) {
        printf("VirtualAllocEx error code: %d\r\n", GetLastError());
        CloseHandle(openedProcess);
        return 0;
    }
    int countWrited = WriteProcessMemory(openedProcess, argLoadLibrary, dllName, strlen(dllName), NULL);
    if (countWrited == NULL) {
        printf("WriteProcessMemory error code: %d\r\n", GetLastError());
        CloseHandle(openedProcess);
        return 0;
    }
    // Создаем поток, передаем адрес LoadLibrary и адрес ее аргумента
    HANDLE threadID = CreateRemoteThread(openedProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, argLoadLibrary, NULL, NULL);
    if (threadID == NULL) {
        printf("CreateRemoteThread error code: %d\r\n", GetLastError());
        CloseHandle(openedProcess);
        return 0;
    }
    // Закрываем поток.
    CloseHandle(openedProcess);
    return 1;
}
int findText(std::vector <std::string> input, int num_arg, std::string toFind) {
    for (int i = 0; i < num_arg; i++)
        if (input[i] == toFind) return i;
    return -1;
}
int main(int argc, char* argv[])
{
    if (!IsUserAnAdmin()) {
        printf("Administrator privileges required\n");
        return 0;
    }
    if (argc < 5) {
        printf("Bad arguments");
        return 0;
    }
    std::vector <std::string> input;
    std::string sendStr;
    for (int i = 0; i < argc - 1; i++)
        input.push_back(argv[i + 1]);
    std::string pidOrName, funkOrHide;
    int funcRet, itsPid = 0, itsFunc = 0;
    DWORD pid;
    if ((funcRet = findText(input, argc - 2, "-pid")) != -1) {//find -pid
        pidOrName = input[funcRet + 1];
        itsPid = 1;
    }//or
    else if ((funcRet = findText(input, argc - 2, "-name")) != -1)
        pidOrName = input[funcRet + 1];//find -name
    else {
        printf("-pid or -name not found");
        return 0;
    }
    if ((funcRet = findText(input, argc - 2, "-func")) != -1) {//find -func
        funkOrHide = input[funcRet + 1];
        itsFunc = 1;
    }//or
    else if ((funcRet = findText(input, argc - 2, "-hide")) != -1)//find -hide
        funkOrHide = input[funcRet + 1];
    else {
        printf("-func or -hide not found");
        return 0;
    }
    if (itsPid) pid = atoi(pidOrName.c_str());
    else pid = getPidByName(pidOrName);
    if (!pid) {
        printf("Process not found");
        return 0;
    }
    for (u_int i = 0; i < input.size() - 1; i++) {
        sendStr += input[i];
        sendStr += " ";
    }
    sendStr += input[input.size() - 1];
    
    WSADATA wsaData;
    SOCKET ListenSocket, ClientSocket;       // впускающий сокет и сокет для клиентов
    sockaddr_in ServerAddr;                  //  адрес сервера
    int err, maxlen = 512;                   // код ошибки и размер буферов
    char* recvbuf = new char[maxlen];        // буфер приема
    char* result_string = new char[maxlen];  // буфер отправки
    // Initialize Winsock
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    // Create a SOCKET for connecting to server
    ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    // Setup the TCP listening socket
    ServerAddr.sin_family = AF_INET;
    InetPton(AF_INET, _T("127.0.0.1"), &ServerAddr.sin_addr.s_addr);
    ServerAddr.sin_port = htons(9000);
    err = bind(ListenSocket, (sockaddr*)&ServerAddr, sizeof(ServerAddr));
    if (err == SOCKET_ERROR) {
        printf("bind failed: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    err = listen(ListenSocket, 50);
    if (err == SOCKET_ERROR) {
        printf("listen failed: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    if (!LoadLibByPID(pid))
        return 0;
    // Accept a client socket
    ClientSocket = accept(ListenSocket, NULL, NULL);
    err = recv(ClientSocket, recvbuf, maxlen, 0);
    if (err > 0) {
        recvbuf[err] = 0;
        printf("Connected\n");
        send(ClientSocket, sendStr.c_str(), strlen(sendStr.c_str())+1, 0);
        printf("Reply sent\n");
    }
    else {
        printf("recv failed: %d\n", WSAGetLastError());
        closesocket(ClientSocket);
        WSACleanup();
        return 0;
    }
    if (itsFunc) while (1) {
        err = recv(ClientSocket, recvbuf, maxlen, 0);
        if (err > 0) {
            recvbuf[err] = 0;
        }
        else if (err == 0) {
            printf("Connection closing...\n");
            break;
        }
        else {
            printf("recv failed: %d\n", WSAGetLastError());
            closesocket(ClientSocket);
            WSACleanup();
            return 1;
        }
        printf("%s",recvbuf);
    }
    // shutdown the connection since we're done
    closesocket(ClientSocket);
    WSACleanup();
    return 1;
}