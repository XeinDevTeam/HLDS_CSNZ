#include "hook.h"
#include "hookutils.h"
#include <stdio.h>
#include <ICommandLine.h>
#include <string>
#include <regex>
#include <sstream>
#include <winsock2.h>
#include <ws2tcpip.h>

DWORD g_dwEngineBase;
DWORD g_dwEngineSize;

DWORD g_dwMpBase;
DWORD g_dwMpSize;

#define SOCKETMANAGER_SIG_CSNZ23 "\xE8\x00\x00\x00\x00\xEB\x00\x33\xC0\xA3\x00\x00\x00\x00\xB9"
#define SOCKETMANAGER_MASK_CSNZ23 "x????x?xxx????x"

#define PACKET_HACK_PARSE_SIG_CSNZ "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x00\x53\x56\x57\xA1\x00\x00\x00\x00\x33\xC5\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\xD9\x89\x5D\x00\x8B\x45\x00\x89\x45\x00\x8B\x45\x00\xC7\x45\x00\x00\x00\x00\x00\xC7\x45\x00\x00\x00\x00\x00\x89\x45\x00\x6A\x00\x8D\x45\x00\xC7\x45\x00\x00\x00\x00\x00\x50\x8D\x4D\x00\xE8\x00\x00\x00\x00\x0F\xB6\x45\x00\x89\x43\x00\x83\xE8"
#define PACKET_HACK_PARSE_MASK_CSNZ "xxxx?x????xx????xxx?xxxx????xxxxx?xx????xxxx?xx?xx?xx?xx?????xx?????xx?x?xx?xx?????xxx?x????xxx?xx?xx"

#define PACKET_HACK_SEND_SIG_CSNZ "\xE8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xEB\x00\x43\x56\x20\x20\x0D"
#define PACKET_HACK_SEND_MASK_CSNZ "x????x????x?xxxxx"

#define BOT_MANAGER_PTR_SIG_CSNZ "\xA3\x00\x00\x00\x00\xC7\x45\x00\x00\x00\x00\x00\xFF\x15\x00\x00\x00\x00\x83\xC4"
#define BOT_MANAGER_PTR_MASK_CSNZ "x????xx?????xx????xx"

#define LOGTOERRORLOG_SIG_CSNZ "\x55\x8B\xEC\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x56\x8B\x75\x00\x8D\x45\x00\x50\x6A\x00\xFF\x75\x00\x8D\x85\x00\x00\x00\x00\x68\x00\x00\x00\x00\x50\xE8\x00\x00\x00\x00\x8B\x10\xFF\x70\x00\x83\xCA\x00\x52\xFF\x15\x00\x00\x00\x00\x83\xC4"
#define LOGTOERRORLOG_MASK_CSNZ "xxxxx????x????xxxx?xxx?xx?xx?xx?xx????x????xx????xxxx?xx?xxx????xx"

#define GETSSLPROTOCOLNAME_SIG_CSNZ "\xE8\x00\x00\x00\x00\xB9\x00\x00\x00\x00\x8A\x10"
#define GETSSLPROTOCOLNAME_MASK_CSNZ "x????x????xx"

#define SOCKETCONSTRUCTOR_SIG_CSNZ "\xE8\x00\x00\x00\x00\xEB\x00\x33\xC0\x53\xFF\xB5"
#define SOCKETCONSTRUCTOR_MASK_CSNZ "x????x?xxxxx"

#define EVP_CIPHER_CTX_NEW_SIG_CSNZ "\xE8\x00\x00\x00\x00\x8B\xF8\x89\xBE"
#define EVP_CIPHER_CTX_NEW_MASK_CSNZ "x????xxxx"

#define PACKET_VOXEL_PARSE_SIG_CSNZ "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x56\x57\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\xF9\x89\xBD\x00\x00\x00\x00\x8B\x45\x00\x33\xF6\x89\xB5\x00\x00\x00\x00\x89\x85\x00\x00\x00\x00\x8B\x45\x00\xC7\x85\x00\x00\x00\x00\x00\x00\x00\x00\x89\xB5\x00\x00\x00\x00\x89\x85\x00\x00\x00\x00\x6A\x00\x8D\x85\x00\x00\x00\x00\x89\x75\x00\x50\x8D\x8D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x0F\xB6\x8D"
#define PACKET_VOXEL_PARSE_MASK_CSNZ "xxxx?x????xx????xxx????x????xxxx?xxxxx?xx????xxxx????xx?xxxx????xx????xx?xx????????xx????xx????x?xx????xx?xxx????x????xxx"

#define VOXEL_LOADWORLD_SIG_CSNZ "\x55\x8B\xEC\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x83\x3D\x00\x00\x00\x00\x00\x0F\x84\x00\x00\x00\x00\x83\x3D\x00\x00\x00\x00\x00\x56"
#define VOXEL_LOADWORLD_MASK_CSNZ "xxxxx????x????xxxx?xx?????xx????xx?????x"

#define VOXELADAPTER_PTR_SIG_CSNZ "\xE8\x00\x00\x00\x00\x83\xFE\x00\x7C"
#define VOXELADAPTER_PTR_MASK_CSNZ "x????xx?x"

#define VOXELWORLD_PTR_SIG_CSNZ "\x83\x3D\x00\x00\x00\x00\x00\x0F\x84\x00\x00\x00\x00\x83\x3D\x00\x00\x00\x00\x00\x56"
#define VOXELWORLD_PTR_MASK_CSNZ "xx?????xx????xx?????x"

char g_pVxlPath[MAX_PATH];
bool g_bUseSSL = false;
std::string voxelVxlURL;

cl_enginefunc_t* g_pEngine;

class CCSBotManager
{
public:
	virtual void Unknown() = NULL;
	virtual void Bot_Add(int side) = NULL;
};

CCSBotManager* g_pBotManager = NULL;;

typedef void*(*tEVP_CIPHER_CTX_new)();
tEVP_CIPHER_CTX_new g_pfnEVP_CIPHER_CTX_new;

typedef void* (*tCVoxelAdapter)();
tCVoxelAdapter g_pVoxelAdapter;

class CVoxelWorld
{
};

CVoxelWorld* g_pVoxelWorld = NULL;

#pragma region Nexon NGClient
char NGClient_Return1()
{
	return 1;
}

void NGClient_Void()
{
}
#pragma endregion

CreateHookClass(void*, SocketManagerConstructor, bool useSSL)
{
	return g_pfnSocketManagerConstructor(ptr, g_bUseSSL);
}

int __fastcall Hook_Packet_Hack_Parse(void* _this, int a2, void* packetBuffer, int packetSize)
{
	return 1;
}

void CSO_Bot_Add()
{
	// get current botmgr ptr
	DWORD dwBotManagerPtr = FindPattern(BOT_MANAGER_PTR_SIG_CSNZ, BOT_MANAGER_PTR_MASK_CSNZ, g_dwMpBase, g_dwMpBase + g_dwMpSize, 1);
	if (!dwBotManagerPtr)
	{
		g_pEngine->Con_Printf("CSO_Bot_Add: dwBotManagerPtr == NULL\n");
		return;
	}
	g_pBotManager = **((CCSBotManager***)(dwBotManagerPtr));

	int side = 0;
	int argc = g_pEngine->Cmd_Argc();
	if (argc > 0)
	{
		side = atoi(g_pEngine->Cmd_Argv(1));
	}
	g_pBotManager->Bot_Add(side);
}

CreateHookClass(const char*, GetSSLProtocolName)
{
	return "None";
}

CreateHookClassType(void*, SocketConstructor, int, int a2, int a3, char a4)
{
	*(DWORD*)((int)ptr + 72) = (DWORD)g_pfnEVP_CIPHER_CTX_new();
	*(DWORD*)((int)ptr + 76) = (DWORD)g_pfnEVP_CIPHER_CTX_new();
	*(DWORD*)((int)ptr + 80) = (DWORD)g_pfnEVP_CIPHER_CTX_new();
	*(DWORD*)((int)ptr + 84) = (DWORD)g_pfnEVP_CIPHER_CTX_new();

	return g_pfnSocketConstructor(ptr, a2, a3, a4);
}

CreateHook(__cdecl, void, LogToErrorLog, void* pLogFile, char* fmt, ...)
{
	char outputString[4096];

	va_list va;
	va_start(va, fmt);
	_vsnprintf_s(outputString, sizeof(outputString), fmt, va);
	outputString[4095] = 0;
	va_end(va);

	printf("[LogToErrorLog] %s", outputString);

	g_pfnLogToErrorLog(pLogFile, outputString);
}

std::string readStr(char* buffer, int offset)
{
	std::string result;

	char curChar = buffer[offset]; offset++;
	while (curChar != '\0')
	{
		result += curChar;
		curChar = buffer[offset]; offset++;
	}

	return result;
}

CreateHookClass(int, Packet_Voxel_Parse, void* packetBuffer, int packetSize)
{
	int type = *(unsigned char*)packetBuffer;
	if (type == 20)
		voxelVxlURL = readStr((char*)packetBuffer, 1);

	return g_pfnPacket_Voxel_Parse(ptr, packetBuffer, packetSize);
}

static const int TIMEOUT = 3000;

CreateHookClass(void, Voxel_LoadWorld)
{
	// get current voxelworld ptr
	DWORD dwVoxelWorldPtr = FindPattern(VOXELWORLD_PTR_SIG_CSNZ, VOXELWORLD_PTR_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, 2);
	if (!dwVoxelWorldPtr)
	{
		g_pEngine->Con_Printf("Voxel_LoadWorld: dwVoxelWorldPtr == NULL\n");
		return g_pfnVoxel_LoadWorld(ptr);
	}
	g_pVoxelWorld = **((CVoxelWorld***)(dwVoxelWorldPtr));

	if (g_pVoxelWorld && g_pVoxelAdapter)
	{
		LPCWCH* lpWideCharStr = (LPCWCH*)malloc(MAX_PATH);

		(*(void(__thiscall**)(int, LPCWCH*))(*(DWORD*)g_pVoxelAdapter() + 252))((int)g_pVoxelAdapter(), lpWideCharStr);

		int size_needed = WideCharToMultiByte(CP_UTF8, 0, lpWideCharStr[0], (int)wcslen(lpWideCharStr[0]), NULL, 0, NULL, NULL);
		std::string vxlFileName(size_needed, 0);
		WideCharToMultiByte(CP_UTF8, 0, lpWideCharStr[0], (int)wcslen(lpWideCharStr[0]), &vxlFileName[0], size_needed, NULL, NULL);

		free(lpWideCharStr);
		lpWideCharStr = NULL;

		std::string voxelVxlDomain;
		std::regex r("https?:\\/\\/(?:www\\.)?([-a-zA-Z0-9@:%._\\+~#=]{1,256})");
		std::smatch sm;
		regex_search(voxelVxlURL, sm, r);
		voxelVxlDomain = sm[1];

		struct hostent* he;
		he = gethostbyname(voxelVxlDomain.c_str());

		if (he != NULL)
		{
			sockaddr_in servaddr;
			memset(&servaddr, 0, sizeof(servaddr));
			servaddr.sin_family = AF_INET;
			if (inet_pton(AF_INET, inet_ntoa(*((struct in_addr*)he->h_addr_list[0])), &servaddr.sin_addr) == 0)
			{
				return g_pfnVoxel_LoadWorld(ptr);
			}
			servaddr.sin_port = htons(80);

			SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

			setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&TIMEOUT), sizeof(TIMEOUT));

			if (sock < 0)
			{
				return g_pfnVoxel_LoadWorld(ptr);
			}

			if (connect(sock, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
			{
				closesocket(sock);
				return g_pfnVoxel_LoadWorld(ptr);
			}

			std::string voxelVxlSuffix = sm.suffix();
			std::string vxlId = vxlFileName.substr(vxlFileName.size() - 24, 20);

			char buffer[2000];
			snprintf(buffer, 2000, voxelVxlSuffix.c_str(), vxlId.c_str());

			std::stringstream ss;
			ss << "GET " << buffer << " HTTP/1.1\r\n"
				<< "Connection: Keep-Alive\r\n"
				<< "User-Agent: cpprestsdk/2.10.2\r\n"
				<< "Host: " << voxelVxlDomain.c_str() << "\r\n"
				<< "\r\n\r\n";
			std::string request = ss.str();

			if (send(sock, request.c_str(), request.length(), 0) != (int)request.length())
			{
				closesocket(sock);
				return g_pfnVoxel_LoadWorld(ptr);
			}

			std::string response;
			char c;
			while (recv(sock, &c, 1, 0) > 0)
			{
				response.push_back(c);
			}

			closesocket(sock);

			if (!response.empty())
			{
				size_t pos = response.find("csov");
				std::string vxlBuffer = response.substr(pos, response.size() - pos);
				if (!vxlBuffer.empty())
				{
					CreateDirectory(vxlFileName.substr(0, vxlFileName.size() - 24).c_str(), NULL);

					FILE* file = fopen(vxlFileName.c_str(), "wb");
					if (file)
					{
						fwrite(vxlBuffer.data(), vxlBuffer.size(), 1, file);
						fclose(file);
					}
					else
					{
						return g_pfnVoxel_LoadWorld(ptr);
					}
				}
			}
		}
	}

	return g_pfnVoxel_LoadWorld(ptr);
}

void Init(HMODULE hModule)
{
	g_dwEngineBase = GetModuleBase(hModule);
	g_dwEngineSize = GetModuleSize(hModule);

	g_bUseSSL = CommandLine()->CheckParm("-usessl");

	const char* vxlPath;
	if (CommandLine()->CheckParm("-vxlpath", &vxlPath) && vxlPath)
		strncpy(g_pVxlPath, vxlPath, sizeof(g_pVxlPath));
}

DWORD WINAPI HookThread(LPVOID lpThreadParameter)
{
	while (!g_dwMpBase) // wait for mp.dll module
	{
		g_dwMpBase = (DWORD)GetModuleHandle("mp.dll");
		Sleep(500);
	}
	g_dwMpSize = GetModuleSize(GetModuleHandle("mp.dll"));

	return TRUE;
}

void Hook(HMODULE hModule)
{
	Init(hModule);

	DWORD find = NULL;
	void* dummy = NULL;

	find = FindPattern(PACKET_HACK_SEND_SIG_CSNZ, PACKET_HACK_SEND_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "Packet_Hack_Send == NULL!!!", "Error", MB_OK);
	else
	{
		InlineHookFromCallOpcode((void*)find, NGClient_Void, dummy, dummy);
		InlineHookFromCallOpcode((void*)(find + 0x5), NGClient_Return1, dummy, dummy);
	}

	find = FindPattern(PACKET_HACK_PARSE_SIG_CSNZ, PACKET_HACK_PARSE_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "Packet_Hack_Parse == NULL!!!", "Error", MB_OK);
	else
		InlineHook((void*)find, Hook_Packet_Hack_Parse, dummy);

	find = FindPattern(SOCKETMANAGER_SIG_CSNZ23, SOCKETMANAGER_MASK_CSNZ23, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "SocketManagerConstructor == NULL!!!", "Error", MB_OK);
	else
		InlineHookFromCallOpcode((void*)find, Hook_SocketManagerConstructor, (void*&)g_pfnSocketManagerConstructor, dummy);

	find = FindPattern(LOGTOERRORLOG_SIG_CSNZ, LOGTOERRORLOG_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "LogToErrorLog == NULL!!!", "Error", MB_OK);
	else
		InlineHook((void*)find, Hook_LogToErrorLog, (void*&)g_pfnLogToErrorLog);

	g_pEngine = (cl_enginefunc_t*)(PVOID) * (PDWORD)(FindPush(g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, (PCHAR)("ScreenFade")) + 0x0D);
	if (!g_pEngine)
		MessageBox(NULL, "g_pEngine == NULL!!!", "Error", MB_OK);
	else
		g_pEngine->pfnAddCommand("cso_bot_add", CSO_Bot_Add);

	if (!g_bUseSSL)
	{
		// hook GetSSLProtocolName to make Crypt work
		find = FindPattern(GETSSLPROTOCOLNAME_SIG_CSNZ, GETSSLPROTOCOLNAME_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "GetSSLProtocolName == NULL!!!", "Error", MB_OK);
		else
			InlineHookFromCallOpcode((void*)find, Hook_GetSSLProtocolName, (void*&)g_pfnGetSSLProtocolName, dummy);

		// hook SocketConstructor to create ctx objects
		find = FindPattern(SOCKETCONSTRUCTOR_SIG_CSNZ, SOCKETCONSTRUCTOR_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "SocketConstructor == NULL!!!", "Error", MB_OK);
		else
			InlineHookFromCallOpcode((void*)find, Hook_SocketConstructor, (void*&)g_pfnSocketConstructor, dummy);

		find = FindPattern(EVP_CIPHER_CTX_NEW_SIG_CSNZ, EVP_CIPHER_CTX_NEW_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "EVP_CIPHER_CTX_new == NULL!!!", "Error", MB_OK);
		else
		{
			DWORD dwCreateCtxAddr = find + 1;
			g_pfnEVP_CIPHER_CTX_new = (tEVP_CIPHER_CTX_new)(dwCreateCtxAddr + 4 + *(DWORD*)dwCreateCtxAddr);
		}
	}

	find = FindPattern(PACKET_VOXEL_PARSE_SIG_CSNZ, PACKET_VOXEL_PARSE_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "Packet_Voxel_Parse == NULL!!!", "Error", MB_OK);
	else
		InlineHook((void*)find, Hook_Packet_Voxel_Parse, (void*&)g_pfnPacket_Voxel_Parse);

	find = FindPattern(VOXEL_LOADWORLD_SIG_CSNZ, VOXEL_LOADWORLD_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "Voxel_LoadWorld == NULL!!!", "Error", MB_OK);
	else
		InlineHook((void*)find, Hook_Voxel_LoadWorld, (void*&)g_pfnVoxel_LoadWorld);

	find = FindPattern(VOXELADAPTER_PTR_SIG_CSNZ, VOXELADAPTER_PTR_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "VoxelAdapter_Ptr == NULL!!!", "Error", MB_OK);
	else
	{
		DWORD dwVoxelAdapterAddr = find + 1;
		g_pVoxelAdapter = (tCVoxelAdapter)(dwVoxelAdapterAddr + 4 + *(DWORD*)dwVoxelAdapterAddr);
	}

	// patch 1000 fps limit
	find = FindPush(g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, "%3i fps -- host(%3.0f) sv(%3.0f) cl(%3.0f) gfx(%3.0f) snd(%3.0f) ents(%d)\n", 2);
	DWORD patchAddr = find - 0x424;
	BYTE patch[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
	WriteMemory((void*)patchAddr, (BYTE*)patch, sizeof(patch));

	// create thread to wait for mp.dll
	CreateThread(NULL, 0, HookThread, NULL, 0, 0);
}

void Unhook()
{
	FreeAllHook();
}