// ========================================================================================================================
// SslCat
//
// Copyright ©2007-2008 Liam Kirton <liam@int3.ws>
// ========================================================================================================================
// SslCat.cpp
//
// Created: 31/05/2007
// ========================================================================================================================

#define SECURITY_WIN32

#include <winsock2.h>
#include <windows.h>

#include <schnlsp.h>
#include <security.h>

#include <algorithm>
#include <iostream>
#include <string>

// ========================================================================================================================

const char *c_SslCatVersion = "0.2.1";

// ========================================================================================================================

BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType);
DWORD WINAPI ConsoleThreadProc(LPVOID lpParameter);

void InitiateHandshake(char *buffer, unsigned int length);
void ContinueHandshake(char *buffer, unsigned int length);

void GetNewClientCredentials();

void PrintConnectionInformation();
void PrintUsage();

void Recv(char *buffer, unsigned int length);
void Send(char *buffer, unsigned int length);

// ========================================================================================================================

HANDLE g_hExitEvent = NULL;
HANDLE g_hConsoleThread = NULL;

CRITICAL_SECTION g_ConsoleCriticalSection;

unsigned int g_Ip = 0;
unsigned short g_Port = 0;

SOCKET g_hAcceptSocket = INVALID_SOCKET;
SOCKET g_hSocket = INVALID_SOCKET;

SCHANNEL_CRED g_sChannelCred;
CredHandle g_hCreds;
CtxtHandle g_hContext;
HCERTSTORE g_hMyCertStore = NULL;

HANDLE g_SendBufferMutex = NULL;
char *g_SendBuffer;
unsigned int g_SendBufferCount;
unsigned int g_SendBufferSize;

char *g_ExtraBuffer;
unsigned int g_ExtraBufferCount;

bool g_bSslHandshakeInitiated = false;
bool g_bSslHandshakeComplete = false;
bool g_bListen = false;
bool g_bVerbose = false;

// ========================================================================================================================

int main(int argc, char *argv[])
{
	std::cout << std::endl
			  << "SslCat " << c_SslCatVersion << std::endl
			  << "Copyright \xB8" << "2007-2008 Liam Kirton <liam@int3.ws>" << std::endl
			  << std::endl
			  << "Built at " << __TIME__ << " on " << __DATE__ << std::endl << std::endl;

	DWORD dwProtocol = 0;
	DWORD dwCipher = 0;

	try
	{
		for(int i = 1; i < argc; ++i)
		{
			std::string cmd = argv[i];
			std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);

			if((cmd == "/target") && ((i + 1) < argc))
			{
				g_Ip = inet_addr(argv[++i]);
			}
			else if((cmd == "/port") && ((i + 1) < argc))
			{
				g_Port = static_cast<unsigned short>(strtol(argv[++i], NULL, 10));
			}
			else if(cmd == "/ssl2")
			{
				dwProtocol |= SP_PROT_SSL2;
			}
			else if(cmd == "/ssl3")
			{
				dwProtocol |= SP_PROT_SSL3;
			}
			else if(cmd == "/tls1")
			{
				dwProtocol |= SP_PROT_TLS1;
			}
			else if((cmd == "/cipher") && ((i + 1) < argc))
			{
				dwCipher = strtol(argv[++i], NULL, 10);
			}
			else if(cmd == "/listen")
			{
				g_bListen = true;
			}
			else if(cmd == "/verbose")
			{
				g_bVerbose = true;
			}
			else 
			{
				throw std::exception("Unknown Command.");
			}
		}

		if(((g_Ip == 0) && !g_bListen) || (g_Port == 0))
		{
			throw std::exception("Either /Target & /Port or /Port & /Listen Required.");
		}
	}
	catch(const std::exception &e)
	{
		PrintUsage();

		std::cout << "Error: " << e.what() << std::endl;
		return -1;
	}	
	
	WSADATA wsaData;
	if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		std::cout << "Fatal Error: WSAStartup() Failed." << std::endl;
		return -1;
	}

	InitializeCriticalSection(&g_ConsoleCriticalSection);
	SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

	if((g_hExitEvent = CreateEvent(NULL, TRUE, FALSE, NULL)) == NULL)
	{
		throw std::exception("CreateEvent() Failed.");
	}

	if((g_SendBufferMutex = CreateMutex(NULL, FALSE, NULL)) == NULL)
	{
		throw std::exception("CreateMutex() Failed.");
	}

	g_SendBufferSize = 1024;
	g_SendBufferCount = 0;
	g_SendBuffer = new char[g_SendBufferSize];

	if((g_hConsoleThread = CreateThread(NULL, 0, ConsoleThreadProc, NULL, 0, NULL)) == NULL)
	{
		throw std::exception("CreateThread() Failed.");
	}

	do
	{
		try
		{
			SecureZeroMemory(&g_hCreds, sizeof(CredHandle));
			SecureZeroMemory(&g_hContext, sizeof(CtxtHandle));

			SecureZeroMemory(&g_sChannelCred, sizeof(SCHANNEL_CRED));
			g_sChannelCred.dwVersion = SCHANNEL_CRED_VERSION;
			g_sChannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
			g_sChannelCred.dwMaximumCipherStrength = dwCipher;
			g_sChannelCred.grbitEnabledProtocols = dwProtocol;

			PCCERT_CONTEXT pCertContext = NULL;

			if(g_bListen)
			{
				g_hMyCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
											   X509_ASN_ENCODING,
											   0,
											   CERT_SYSTEM_STORE_LOCAL_MACHINE,
											   L"MY");
				if(g_hMyCertStore == NULL)
				{
					throw std::exception("CertOpenStore() Failed.");
				}

				pCertContext = CertFindCertificateInStore(g_hMyCertStore,
														  X509_ASN_ENCODING,
														  0,
														  CERT_FIND_SUBJECT_STR_A,
														  L"SslCat",
														  NULL);
				if(pCertContext == NULL)
				{
					throw std::exception("CertFindCertificateInStore() Failed.");
				}

				g_sChannelCred.cCreds = 1;
				g_sChannelCred.paCred = &pCertContext;
			}
			
			if(AcquireCredentialsHandle(NULL,
										UNISP_NAME,
										g_bListen ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND,
										NULL,
										&g_sChannelCred,
										NULL,
										NULL,
										&g_hCreds,
										NULL) != SEC_E_OK)
			{
				throw std::exception("AcquireCredentialsHandle() Failed.");
			}

			if(pCertContext != NULL)
			{
				CertFreeCertificateContext(pCertContext);
				pCertContext = NULL;
			}

			g_hAcceptSocket = INVALID_SOCKET;
			g_hSocket = INVALID_SOCKET;

			g_bSslHandshakeInitiated = false;
			g_bSslHandshakeComplete = false;

			g_ExtraBuffer = NULL;
			g_ExtraBufferCount = 0;

			if((g_hSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0)) == INVALID_SOCKET)
			{
				throw std::exception("WSASocket() Failed.");
			}

			sockaddr_in sockAddrInBind;
			sockAddrInBind.sin_family = AF_INET;
			sockAddrInBind.sin_addr.s_addr = htonl(INADDR_ANY);
			sockAddrInBind.sin_port = g_bListen ? htons(g_Port) : htons(0);
			
			if(bind(g_hSocket, reinterpret_cast<sockaddr *>(&sockAddrInBind), sizeof(sockaddr_in)) == SOCKET_ERROR)
			{
				throw std::exception("bind() Failed.");
			}

			if(g_bListen)
			{
				g_hAcceptSocket = g_hSocket;
				g_hSocket = INVALID_SOCKET;

				if(listen(g_hAcceptSocket, 0) == SOCKET_ERROR)
				{
					throw std::exception("listen() Failed.");
				}
			}
			else
			{
				sockaddr_in sockAddrInConnect;
				SecureZeroMemory(&sockAddrInConnect, sizeof(sockaddr_in));
				sockAddrInConnect.sin_family = AF_INET;
				sockAddrInConnect.sin_port = htons(g_Port);
				sockAddrInConnect.sin_addr.s_addr = g_Ip;

				if(connect(g_hSocket, reinterpret_cast<const sockaddr *>(&sockAddrInConnect), sizeof(sockaddr_in)) == SOCKET_ERROR)
				{
					throw std::exception("connect() Failed.");
				}

				InitiateHandshake(NULL, 0);
			}

			while(WaitForSingleObject(g_hExitEvent, 0) != WAIT_OBJECT_0)
			{
				char buffer[65535];
				SecureZeroMemory(&buffer, sizeof(buffer));
				int bytesRecvd = 0;

				fd_set readSet;
				FD_ZERO(&readSet);
				FD_SET((g_hSocket != INVALID_SOCKET) ? g_hSocket : g_hAcceptSocket, &readSet);

				timeval timeout = {0, 100};
				switch(select(0, &readSet, NULL, NULL, &timeout))
				{
					case 1:
						if(g_hSocket == INVALID_SOCKET)
						{
							sockaddr_in sockAddrInAccept;
							int sockAddrInAcceptSize = sizeof(sockaddr_in);
							SecureZeroMemory(&sockAddrInAccept, sizeof(sockaddr_in));

							if((g_hSocket = accept(g_hAcceptSocket, reinterpret_cast<sockaddr *>(&sockAddrInAccept), &sockAddrInAcceptSize)) == SOCKET_ERROR)
							{
								throw std::exception("listen() Failed.");
							}

							std::cout << "Host "
									  << (sockAddrInAccept.sin_addr.S_un.S_addr & 0x000000FF) << "."
									  << ((sockAddrInAccept.sin_addr.S_un.S_addr & 0x0000FF00) >> 8) << "."
									  << ((sockAddrInAccept.sin_addr.S_un.S_addr & 0x00FF0000) >> 16) << "."
									  << ((sockAddrInAccept.sin_addr.S_un.S_addr & 0xFF000000) >> 24) << ":"
									  << ntohs(sockAddrInAccept.sin_port) << " Connected." << std::endl << std::endl;
						}
						else
						{
							bytesRecvd = recv(g_hSocket, reinterpret_cast<char *>(&buffer), sizeof(buffer), 0);
							if(bytesRecvd <= 0)
							{
								throw std::exception("Disconnected.");
							}
							else
							{
								Recv(reinterpret_cast<char *>(&buffer), bytesRecvd);
							}
						}
						break;

					case SOCKET_ERROR:
						throw std::exception("select() Failed.");
				}

				if((g_bSslHandshakeComplete) && (g_SendBufferCount > 0))
				{
					WaitForSingleObject(g_SendBufferMutex, INFINITE);
					
					unsigned int tmpSendBufferSize = g_SendBufferCount;
					char *tmpSendBuffer = new char[g_SendBufferCount];
					RtlCopyMemory(tmpSendBuffer, g_SendBuffer, tmpSendBufferSize);

					SecureZeroMemory(g_SendBuffer, g_SendBufferSize);
					g_SendBufferCount = 0;

					ReleaseMutex(g_SendBufferMutex);

					EnterCriticalSection(&g_ConsoleCriticalSection);
					for(unsigned int i = 0; i < tmpSendBufferSize; ++i)
					{
						std::cout << tmpSendBuffer[i] << std::flush;
					}
					LeaveCriticalSection(&g_ConsoleCriticalSection);
				
					Send(tmpSendBuffer, tmpSendBufferSize);
					delete [] tmpSendBuffer;
				}
			}
		}
		catch(const std::exception &e)
		{
			std::cout << std::endl << "Caught Exception: " << e.what() << std::endl << std::endl;
		}

		if(g_hAcceptSocket != INVALID_SOCKET)
		{
			closesocket(g_hAcceptSocket);
			g_hSocket = INVALID_SOCKET;
		}
		if(g_hSocket != INVALID_SOCKET)
		{
			closesocket(g_hSocket);
			g_hSocket = INVALID_SOCKET;
		}

		DeleteSecurityContext(&g_hContext);
		FreeCredentialsHandle(&g_hCreds);

		if(g_hMyCertStore != NULL)
		{
			CertCloseStore(g_hMyCertStore, 0);
			g_hMyCertStore = NULL;
		}

		delete [] g_ExtraBuffer;
		g_ExtraBuffer = NULL;
		g_ExtraBufferCount = 0;
	}
	while(g_bListen && (WaitForSingleObject(g_hExitEvent, 0) != WAIT_OBJECT_0));
	
	WSACleanup();

	SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
	DeleteCriticalSection(&g_ConsoleCriticalSection);

	return 0;
}

// ========================================================================================================================

BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType)
{
	SetEvent(g_hExitEvent);
	return TRUE;
}

// ========================================================================================================================

DWORD WINAPI ConsoleThreadProc(LPVOID lpParameter)
{
	HANDLE hStdInput = GetStdHandle(STD_INPUT_HANDLE);

	INPUT_RECORD testInputRecord;
	DWORD dwTestInputRecordCount;
	if(PeekConsoleInput(hStdInput, &testInputRecord, 1, &dwTestInputRecordCount) == 0)
	{
		if(ReadFile(hStdInput, g_SendBuffer, g_SendBufferSize, reinterpret_cast<LPDWORD>(&g_SendBufferCount), NULL) == 0)
		{
			std::cout << std::endl << "Fatal Error: ReadFile() Failed." << std::endl;
			SetEvent(g_hExitEvent);
			return -1;
		}

		CloseHandle(hStdInput);

		if((hStdInput = CreateFile(L"CONIN$", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
		{
			std::cout << std::endl << "Fatal Error: CreateFile(\"CONIN$\") Failed." << std::endl;
			SetEvent(g_hExitEvent);
			return -1;
		}
	}

	SetConsoleMode(hStdInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT);

	while(WaitForSingleObject(g_hExitEvent, 0) != WAIT_OBJECT_0)
	{
		if(WaitForSingleObject(hStdInput, 0) == WAIT_OBJECT_0)
		{
			INPUT_RECORD inputRecord[1024];
			DWORD dwEventsRead;

			if(ReadConsoleInput(hStdInput, reinterpret_cast<INPUT_RECORD *>(&inputRecord), 1024, &dwEventsRead) != 0)
			{
				WaitForSingleObject(g_SendBufferMutex, INFINITE);

				for(DWORD i = 0; i < dwEventsRead; ++i)
				{
					if((inputRecord[i].EventType == KEY_EVENT) &&
					   (inputRecord[i].Event.KeyEvent.bKeyDown) &&
					   (inputRecord[i].Event.KeyEvent.uChar.AsciiChar != 0))
					{
						char buffer[3];
						SecureZeroMemory(&buffer, sizeof(buffer));

						DWORD dwBufferCount = 0;

						buffer[dwBufferCount++] = inputRecord[i].Event.KeyEvent.uChar.AsciiChar;
						if(inputRecord[i].Event.KeyEvent.uChar.AsciiChar == '\r')
						{
							buffer[dwBufferCount++] = '\n';
						}

						if(g_SendBufferCount + dwBufferCount > g_SendBufferSize)
						{
							g_SendBufferSize = g_SendBufferCount + dwBufferCount;
							char *tmpSendBuffer = new char[g_SendBufferSize];
							RtlCopyMemory(tmpSendBuffer, g_SendBuffer, g_SendBufferCount);
							delete [] g_SendBuffer;
							g_SendBuffer = tmpSendBuffer;
						}

						RtlCopyMemory(g_SendBuffer + g_SendBufferCount, &buffer, dwBufferCount);
						g_SendBufferCount += dwBufferCount;
					}
				}

				ReleaseMutex(g_SendBufferMutex);
			}
		}
		else
		{
			Sleep(50);
		}
	}

	return 0;
}

// ========================================================================================================================

void InitiateHandshake(char *buffer, unsigned int length)
{
	DWORD dwSSPIFlags;
    DWORD dwSSPIOutFlags;
    
    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR |
                  ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

	SecBufferDesc inputBufferDesc;
	SecBuffer inputBuffer;
	inputBufferDesc.ulVersion = SECBUFFER_VERSION;
	inputBufferDesc.cBuffers = 1;
	inputBufferDesc.pBuffers = &inputBuffer;
	inputBuffer.BufferType = SECBUFFER_TOKEN;
	inputBuffer.cbBuffer = length;
	inputBuffer.pvBuffer = buffer;

    SecBufferDesc outputBufferDesc;
	SecBuffer outputBuffer;
	outputBufferDesc.ulVersion = SECBUFFER_VERSION;
	outputBufferDesc.cBuffers = 1;
	outputBufferDesc.pBuffers = &outputBuffer;
	outputBuffer.BufferType = SECBUFFER_TOKEN;
	outputBuffer.cbBuffer = 0;
	outputBuffer.pvBuffer = NULL;

	in_addr addrTarget;
	addrTarget.S_un.S_addr = g_Ip;

	SEC_WCHAR wszTargetName[16];
	MultiByteToWideChar(CP_UTF8, 0, inet_ntoa(addrTarget), -1, reinterpret_cast<LPWSTR>(&wszTargetName), 16);

	SECURITY_STATUS scRet = S_OK;
	if(g_bListen)
	{
		scRet = AcceptSecurityContext(&g_hCreds,
									  NULL,
									  &inputBufferDesc,
									  dwSSPIFlags,
									  SECURITY_NATIVE_DREP,
									  &g_hContext,
									  &outputBufferDesc,
									  &dwSSPIOutFlags,
									  NULL);
	}
	else
	{
		scRet = InitializeSecurityContext(&g_hCreds,
										  NULL,
										  reinterpret_cast<SEC_WCHAR *>(&wszTargetName),
										  dwSSPIFlags,
										  0,
										  SECURITY_NATIVE_DREP,
										  NULL,
										  0,
										  &g_hContext,
										  &outputBufferDesc,
										  &dwSSPIOutFlags,
										  NULL);
	}

	if(scRet != SEC_I_CONTINUE_NEEDED)
	{
		std::cout << "AcceptSecurityContext/InitializeSecurityContext() Returned: 0x" << std::hex << scRet << std::dec << std::endl;
		throw std::exception("AcceptSecurityContext/InitializeSecurityContext() Failed.");
	}

	send(g_hSocket, reinterpret_cast<const char *>(outputBufferDesc.pBuffers[0].pvBuffer), outputBufferDesc.pBuffers[0].cbBuffer, 0);
	FreeContextBuffer(outputBufferDesc.pBuffers[0].pvBuffer);

	g_bSslHandshakeInitiated = true;
}

// ========================================================================================================================

void ContinueHandshake(char *buffer, unsigned int length)
{
	DWORD dwSSPIFlags;
    DWORD dwSSPIOutFlags;
    
    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR |
                  ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

	SecBufferDesc inputBufferDesc;
	SecBuffer inputBuffer[2];

	inputBufferDesc.ulVersion = SECBUFFER_VERSION;
	inputBufferDesc.cBuffers = 2;
	inputBufferDesc.pBuffers = reinterpret_cast<SecBuffer *>(&inputBuffer);

	SecBufferDesc outputBufferDesc;
	SecBuffer outputBuffer;

	outputBufferDesc.ulVersion = SECBUFFER_VERSION;
	outputBufferDesc.cBuffers = 1;
	outputBufferDesc.pBuffers = &outputBuffer;
	outputBuffer.BufferType = SECBUFFER_TOKEN;
	outputBuffer.cbBuffer = 0;
	outputBuffer.pvBuffer = NULL;

	unsigned int recvBufferLength = 0;
	char *recvBuffer = NULL;

	SECURITY_STATUS scRet = SEC_I_CONTINUE_NEEDED;
	while((scRet == SEC_I_CONTINUE_NEEDED) && ((g_ExtraBufferCount + length) > 0))
	{
		delete [] recvBuffer;
		recvBuffer = NULL;

		recvBufferLength = g_ExtraBufferCount + length;
		recvBuffer = new char[recvBufferLength];

		if(g_ExtraBufferCount != 0)
		{
			RtlCopyMemory(recvBuffer, g_ExtraBuffer, g_ExtraBufferCount);
			RtlCopyMemory(recvBuffer + g_ExtraBufferCount, buffer, length);
		}
		else
		{
			RtlCopyMemory(recvBuffer, buffer, length);
		}

		length = 0;
		delete [] g_ExtraBuffer;
		g_ExtraBuffer = NULL;
		g_ExtraBufferCount = 0;

		inputBuffer[0].BufferType = SECBUFFER_TOKEN;
		inputBuffer[0].cbBuffer = recvBufferLength;
		inputBuffer[0].pvBuffer = recvBuffer;
		inputBuffer[1].BufferType = SECBUFFER_EMPTY;
		inputBuffer[1].cbBuffer = 0;
		inputBuffer[1].pvBuffer = NULL;
		
		if(g_bListen)
		{
			scRet = AcceptSecurityContext(&g_hCreds,
										  &g_hContext,
										  &inputBufferDesc,
										  dwSSPIFlags,
										  SECURITY_NATIVE_DREP,
										  &g_hContext,
										  &outputBufferDesc,
										  &dwSSPIOutFlags,
										  NULL);
		}
		else
		{
			scRet = InitializeSecurityContext(&g_hCreds,
											  &g_hContext,
											  NULL,
											  dwSSPIFlags,
											  0,
											  SECURITY_NATIVE_DREP,
											  &inputBufferDesc,
											  0,
											  &g_hContext,
											  &outputBufferDesc,
											  &dwSSPIOutFlags,
											  NULL);
		}

		if((scRet == SEC_E_OK) ||
		   (scRet == SEC_I_CONTINUE_NEEDED) ||
		   (FAILED(scRet) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR)))
		{
			if((outputBuffer.cbBuffer != 0) && (outputBuffer.pvBuffer != NULL))
			{
				send(g_hSocket, reinterpret_cast<const char *>(outputBufferDesc.pBuffers[0].pvBuffer), outputBufferDesc.pBuffers[0].cbBuffer, 0);
				FreeContextBuffer(outputBufferDesc.pBuffers[0].pvBuffer);
				outputBufferDesc.pBuffers[0].pvBuffer = NULL;
				outputBufferDesc.pBuffers[0].cbBuffer = 0;
			}
		}

		if(scRet == SEC_I_INCOMPLETE_CREDENTIALS)
		{
			g_ExtraBufferCount = recvBufferLength;
			g_ExtraBuffer = new char[g_ExtraBufferCount];
			RtlCopyMemory(g_ExtraBuffer, recvBuffer, recvBufferLength);

			GetNewClientCredentials();
			scRet = SEC_I_CONTINUE_NEEDED;
			continue;
		}
		else if(scRet == SEC_E_INCOMPLETE_MESSAGE)
		{
			g_ExtraBufferCount = recvBufferLength;
			g_ExtraBuffer = new char[g_ExtraBufferCount];
			RtlCopyMemory(g_ExtraBuffer, recvBuffer, recvBufferLength);
			break;
		}
		else
		{
			if((inputBuffer[1].BufferType = SECBUFFER_EXTRA) && (inputBuffer[1].cbBuffer > 0))
			{
				g_ExtraBufferCount = inputBuffer[1].cbBuffer;
				g_ExtraBuffer = new char[g_ExtraBufferCount];
				RtlCopyMemory(g_ExtraBuffer, recvBuffer + recvBufferLength - inputBuffer[1].cbBuffer, inputBuffer[1].cbBuffer);
			}
		
			if(scRet == SEC_E_OK)
			{
				EnterCriticalSection(&g_ConsoleCriticalSection);

				if(g_bVerbose)
				{
					PrintConnectionInformation();
					std::cout << std::endl;
				}

				std::cout << "Connected. Press Ctrl+C To Quit." << std::endl << std::endl;
				LeaveCriticalSection(&g_ConsoleCriticalSection);

				g_bSslHandshakeComplete = true;
				break;
			}
			else if(FAILED(scRet))
			{
				std::cout << "AcceptSecurityContext/InitializeSecurityContext() Returned: 0x" << std::hex << scRet << std::dec << std::endl;
				throw std::exception("AcceptSecurityContext/InitializeSecurityContext() Failed.");
			}
		}

		break;
	}

	delete [] recvBuffer;
	recvBuffer = NULL;
}

// ========================================================================================================================

void GetNewClientCredentials()
{
	HCERTSTORE hCertStore;
	if((hCertStore = CertOpenSystemStore(0, L"MY")) == NULL)
	{
		throw std::exception("CertOpenSystemStore(\"MY\") Failed.");
	}

	SecPkgContext_IssuerListInfoEx issuerListInfo;
	SECURITY_STATUS securityStatus = QueryContextAttributes(&g_hContext,
															SECPKG_ATTR_ISSUER_LIST_EX,
															reinterpret_cast<PVOID>(&issuerListInfo));
	if(securityStatus != SEC_E_OK)
	{
		throw std::exception("QueryContextAttributes(SECPKG_ATTR_ISSUER_LIST_EX) Failed.");
	}

	CERT_CHAIN_FIND_BY_ISSUER_PARA findByIssuerPara;
	SecureZeroMemory(&findByIssuerPara, sizeof(CERT_CHAIN_FIND_BY_ISSUER_PARA));
	findByIssuerPara.cbSize = sizeof(CERT_CHAIN_FIND_BY_ISSUER_PARA);
	findByIssuerPara.pszUsageIdentifier =szOID_PKIX_KP_CLIENT_AUTH;
	findByIssuerPara.dwKeySpec = 0;
	findByIssuerPara.cIssuer = issuerListInfo.cIssuers;
	findByIssuerPara.rgIssuer = issuerListInfo.aIssuers;

	while(true)
	{
		PCCERT_CHAIN_CONTEXT pChainContext = NULL;
		pChainContext = CertFindChainInStore(hCertStore,
											 X509_ASN_ENCODING,
											 0,
											 CERT_CHAIN_FIND_BY_ISSUER,
											 &findByIssuerPara,
											 pChainContext);
		if(pChainContext == NULL)
		{
			throw std::exception("CertFindChainInStore() Failed.");
		}

		PCCERT_CONTEXT pCertContext = pChainContext->rgpChain[0]->rgpElement[0]->pCertContext;
		g_sChannelCred.dwVersion = SCHANNEL_CRED_VERSION;
		g_sChannelCred.cCreds = 1;
		g_sChannelCred.paCred = &pCertContext;

		CredHandle hCreds;
		if(AcquireCredentialsHandle(NULL, UNISP_NAME, SECPKG_CRED_OUTBOUND, NULL, &g_sChannelCred, NULL, NULL, &hCreds, NULL) != SEC_E_OK)
		{
			continue;
		}

		FreeCredentialsHandle(&g_hCreds);
		g_hCreds = hCreds;
		break;
	}

	if(hCertStore != NULL)
    {
        CertCloseStore(hCertStore, 0);
		hCertStore = NULL;
    }
}

// ========================================================================================================================

void PrintConnectionInformation()
{
	SecPkgContext_ConnectionInfo connectionInfo;

	PCCERT_CONTEXT pCertContext = NULL;
	if(QueryContextAttributes(&g_hContext,
							  SECPKG_ATTR_REMOTE_CERT_CONTEXT,
							  reinterpret_cast<PVOID>(&pCertContext)) == SEC_E_OK)
	{
		char certName[1024];
		if(!CertNameToStrA(pCertContext->dwCertEncodingType,
						   &pCertContext->pCertInfo->Subject,
						   CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
						   certName,
						   sizeof(certName)))
		{
			throw std::exception("CertNameToStr() Failed.");
		}
		std::cout << "Subject: " << certName << std::endl << std::endl;

		if(!CertNameToStrA(pCertContext->dwCertEncodingType,
						   &pCertContext->pCertInfo->Issuer,
						   CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
						   certName,
						   sizeof(certName)))
		{
			throw std::exception("CertNameToStr() Failed.");
		}
		std::cout << "Issuer: " << certName << std::endl << std::endl;
		
		PCCERT_CONTEXT pCurrentCert = pCertContext;
		while(pCurrentCert != NULL)
		{
			PCCERT_CONTEXT pIssuerCert = NULL;
			DWORD dwVerificationFlags = 0;
			if((pIssuerCert = CertGetIssuerCertificateFromStore(pCertContext->hCertStore,
																pCurrentCert,
																NULL,
																&dwVerificationFlags)) == NULL)
			{
				if(pCurrentCert != pCertContext)
				{
					CertFreeCertificateContext(pCurrentCert);
					pCurrentCert = NULL;
				}
				break;
			}

			if(!CertNameToStrA(pIssuerCert->dwCertEncodingType,
							   &pIssuerCert->pCertInfo->Subject,
							   CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
							   certName,
							   sizeof(certName)))
			{
				throw std::exception("CertNameToStr() Failed.");
			}
			std::cout << "CA Subject: " << certName << std::endl << std::endl;
			
			if(!CertNameToStrA(pIssuerCert->dwCertEncodingType,
							   &pIssuerCert->pCertInfo->Issuer,
							   CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
							   certName,
							   sizeof(certName)))
			{
				throw std::exception("CertNameToStr() Failed.");
			}
			std::cout << "CA Issuer: " << certName << std::endl << std::endl;

			if(pCurrentCert != pCertContext)
			{
				CertFreeCertificateContext(pCurrentCert);
			}
			pCurrentCert = pIssuerCert;
		}

		if(pCertContext != NULL)
		{
			CertFreeCertificateContext(pCertContext);
			pCertContext = NULL;
		}
	}

	std::cout << "Algorithms Negotiated: ";

	if(QueryContextAttributes(&g_hContext,
							  SECPKG_ATTR_CONNECTION_INFO,
							  reinterpret_cast<PVOID>(&connectionInfo)) != SEC_E_OK)
	{
		throw std::exception("QueryContextAttributes(SECPKG_ATTR_CONNECTION_INFO) Failed.");
	}

	switch(connectionInfo.dwProtocol)
	{
		case SP_PROT_PCT1_CLIENT:
		case SP_PROT_PCT1_SERVER:
			std::cout << "PCT1";
			break;
		case SP_PROT_SSL2_CLIENT:
		case SP_PROT_SSL2_SERVER:
			std::cout << "SSL2";
			break;
		case SP_PROT_SSL3_CLIENT:
		case SP_PROT_SSL3_SERVER:
			std::cout << "SSL3";
			break;
		case SP_PROT_TLS1_CLIENT:
		case SP_PROT_TLS1_SERVER:
			std::cout << "TLS1";
			break;
		default:
			std::cout << std::hex
					  << connectionInfo.dwProtocol
					  << std::dec;
			break;
	}

	std::cout << " : ";

	switch(connectionInfo.aiCipher)
	{
		case CALG_DES:
		case CALG_CYLINK_MEK:
			std::cout << "DES";
			break;
		case CALG_3DES:
			std::cout << "3DES";
			break;
		case CALG_RC2:
			std::cout << "RC2";
			break;
		case CALG_RC4:
			std::cout << "RC4";
			break;
		case CALG_SKIPJACK:
			std::cout << "Skipjack";
			break;
		default:
			std::cout << std::hex
					  << connectionInfo.aiCipher
					  << std::dec;
			break;
	}

	std::cout << " : " << connectionInfo.dwCipherStrength << "bit / ";

	switch(connectionInfo.aiHash)
	{
		case CALG_MD5:
			std::cout << "MD5";
			break;
		case CALG_SHA:
			std::cout << "SHA";
			break;
		default:
			std::cout << std::hex
					  << connectionInfo.aiHash
					  << std::dec;
			break;
	}

	std::cout << " : " << connectionInfo.dwHashStrength << "bit / ";

	switch(connectionInfo.aiExch)
	{
		case CALG_RSA_KEYX:
		case CALG_RSA_SIGN:
			std::cout << "RSA";
			break;
		case CALG_KEA_KEYX:
			std::cout << "KEA";
			break;
		case CALG_DH_EPHEM:
			std::cout << "DH";
			break;
		default:
			std::cout << std::hex
					  << connectionInfo.aiExch
					  << std::dec;
			break;
	}

	std::cout << " : " << connectionInfo.dwHashStrength << "bit" << std::endl;
}

// ========================================================================================================================

void PrintUsage()
{
	std::cout << "Usage: SslCat.exe /Target <a.b.c.d> /Port <p>" << std::endl
			  << "                  /Ssl2 /Ssl3 /Tls /Cipher <c> /Listen /Verbose" << std::endl
			  << std::endl;
}

// ========================================================================================================================

void Recv(char *buffer, unsigned int length)
{
	if(!g_bSslHandshakeComplete)
	{
		if(g_bListen)
		{
			if(!g_bSslHandshakeInitiated)
			{
				InitiateHandshake(buffer, length);
				return;
			}
		}
		ContinueHandshake(buffer, length);
		return;
	}

	SecBufferDesc secBufferDesc;
	SecBuffer secBuffer[4];

	secBufferDesc.ulVersion = SECBUFFER_VERSION;
	secBufferDesc.cBuffers = 4;
	secBufferDesc.pBuffers = reinterpret_cast<SecBuffer *>(&secBuffer);

	char *recvBuffer = NULL;

	while((g_ExtraBufferCount + length) > 0)
	{
		delete [] recvBuffer;
		recvBuffer = NULL;

		unsigned int recvBufferLength = g_ExtraBufferCount + length;
		recvBuffer = new char[recvBufferLength];

		if(g_ExtraBufferCount != 0)
		{
			RtlCopyMemory(recvBuffer, g_ExtraBuffer, g_ExtraBufferCount);
			RtlCopyMemory(recvBuffer + g_ExtraBufferCount, buffer, length);
		}
		else
		{
			RtlCopyMemory(recvBuffer, buffer, length);
		}
		
		secBuffer[0].BufferType = SECBUFFER_DATA;
		secBuffer[0].cbBuffer = recvBufferLength;
		secBuffer[0].pvBuffer = recvBuffer;
		secBuffer[1].BufferType = SECBUFFER_EMPTY;
		secBuffer[1].cbBuffer = 0;
		secBuffer[1].pvBuffer = NULL;
		secBuffer[2].BufferType = SECBUFFER_EMPTY;
		secBuffer[2].cbBuffer = 0;
		secBuffer[2].pvBuffer = NULL;
		secBuffer[3].BufferType = SECBUFFER_EMPTY;
		secBuffer[3].cbBuffer = 0;
		secBuffer[3].pvBuffer = NULL;

		SECURITY_STATUS scRet = DecryptMessage(&g_hContext, &secBufferDesc, 0, NULL);

		if(scRet == SEC_E_INCOMPLETE_MESSAGE)
		{
			break;
		}
		else
		{
			delete [] g_ExtraBuffer;
			g_ExtraBuffer = NULL;
			g_ExtraBufferCount = 0;

			length = 0;

			for(DWORD i = 1; i < 4; ++i)
			{
				if(secBuffer[i].BufferType == SECBUFFER_DATA)
				{
					EnterCriticalSection(&g_ConsoleCriticalSection);
					for(unsigned int j = 0; j < secBuffer[i].cbBuffer; ++j)
					{
						std::cout << reinterpret_cast<char *>(secBuffer[i].pvBuffer)[j];
					}
					std::cout << std::flush;
					LeaveCriticalSection(&g_ConsoleCriticalSection);
				}
				else if(secBuffer[i].BufferType == SECBUFFER_EXTRA)
				{
					g_ExtraBufferCount = secBuffer[i].cbBuffer;
					g_ExtraBuffer = new char[g_ExtraBufferCount];

					RtlCopyMemory(g_ExtraBuffer, secBuffer[i].pvBuffer, g_ExtraBufferCount);
				}
			}

			if(scRet == SEC_I_CONTEXT_EXPIRED)
			{
				delete [] recvBuffer;
				recvBuffer = NULL;
				throw std::exception("Disconnected.");
			}
		}
	}

	delete [] recvBuffer;
	recvBuffer = NULL;
}

// ========================================================================================================================

void Send(char *buffer, unsigned int length)
{
	if(!g_bSslHandshakeComplete)
	{
		send(g_hSocket, buffer, length, 0);
		return;
	}

	SecPkgContext_StreamSizes streamSizes;
    if(QueryContextAttributes(&g_hContext, SECPKG_ATTR_STREAM_SIZES, &streamSizes) != SEC_E_OK)
    {
		throw std::exception("QueryContextAttributes() Failed.");
    }
	else if(streamSizes.cbMaximumMessage < length)
	{
		throw std::exception("Send() - Buffer Too Large.");
	}

	DWORD dwSendBufferSize = length + streamSizes.cbHeader + streamSizes.cbTrailer;
	char *sendBuffer = new char[dwSendBufferSize];
	SecureZeroMemory(sendBuffer, dwSendBufferSize);

	RtlCopyMemory(sendBuffer + streamSizes.cbHeader, buffer, length);

	SecBufferDesc secBufferDesc;
	SecBuffer secBuffer[4];

	secBufferDesc.ulVersion = SECBUFFER_VERSION;
	secBufferDesc.cBuffers = 4;
	secBufferDesc.pBuffers = reinterpret_cast<SecBuffer *>(&secBuffer);

	secBuffer[0].BufferType = SECBUFFER_STREAM_HEADER;
	secBuffer[0].cbBuffer = streamSizes.cbHeader;
	secBuffer[0].pvBuffer = sendBuffer;
	secBuffer[1].BufferType = SECBUFFER_DATA;
	secBuffer[1].cbBuffer = length;
	secBuffer[1].pvBuffer = sendBuffer + streamSizes.cbHeader;
	secBuffer[2].BufferType = SECBUFFER_STREAM_TRAILER;
	secBuffer[2].cbBuffer = streamSizes.cbTrailer;
	secBuffer[2].pvBuffer = sendBuffer + streamSizes.cbHeader + length;
	secBuffer[3].BufferType = SECBUFFER_EMPTY;
	secBuffer[3].cbBuffer = 0;
	secBuffer[3].pvBuffer = NULL;

	SECURITY_STATUS scRet = EncryptMessage(&g_hContext, 0, &secBufferDesc, 0);
	if(scRet != SEC_E_OK)
	{
		throw std::exception("EncryptMessage() Failed.");
	}

	send(g_hSocket, sendBuffer, secBuffer[0].cbBuffer + secBuffer[1].cbBuffer + secBuffer[2].cbBuffer, 0);
	
	delete [] sendBuffer;
	sendBuffer = NULL;	
}

// ========================================================================================================================
