//**************************************************************************** 
// Version: None 
// "Coder": WinEggdrop 
// Date Release: NULL 
// Purpose: To Demonstrate Multi-Thread Syn Scan 
// Test PlatForm: Win 2K Pro And Server SP4 
// Compiled On: VC++ 6.0 
// Comment: 
//       You Will See Most The Code Looks Pretty Familiar,Yeap,Those Syn 
//       Scan Or Syn Flood Code Is So Wide-Spread,I Don&#39;t Want To Comment 
//       This Code In Detail.This Code Is Only The Very Basic Stuff,But 
//       You Can Extend Its Features Due To Your Own Interest 
// Notice: 
//       Syn Scan Is Not Very Accurate. 
// Problems: 
//       1.The Code May Not Work On Some Boxes, 
//        Why This Occurs And How To Solve? 
//       2.The Thread May Encounter Dead Lock Situation(Blocking Socket), 
//        Why This Happens And How To Solve? 
//      3.Does Linear-thread have better performance? Check It Out 
//       It&#39;s Your Task To Solve These Two Problems.I Know How To Solve 
//       Them,But I deliberately Leave Them For Those Interesting In 
//       Syn Scan 
//**************************************************************************** 

#include <winsock2.h> 
#include <ws2tcpip.h> 
#include <stdio.h> 
#include <conio.h> 
#define  SIO_RCVALL        _WSAIOW(IOC_VENDOR,1) 

#pragma comment(lib, "ws2_32.lib") 

// Global Variables Declaration 
char  *pHost = NULL; 
int   PortToScan[] = {21,22,23,25,53,79,80,110,111,135,139,445,554,1080,1433,1521,3306,3389,5631,8080}; 
BOOL  *StatusFlag = NULL; 
SOCKET SnifferSocket = INVALID_SOCKET; 
// End Of Global Variables Declaration 

// Structure Declaration 
typedef struct _IP_HEADER          
{ 
unsigned char  h_lenver;       
unsigned char  tos;          
unsigned short  total_len;      
unsigned short  ident;         
unsigned short  frag_and_flags;   
unsigned char  ttl;          
unsigned char  proto;         
unsigned short  checksum;       
unsigned int   sourceIP;       
unsigned int   destIP;        
} IP_HEADER; 

typedef struct _TCP_HEADER         
{ 
USHORT th_sport;             
USHORT th_dport;             
unsigned int th_seq;          
unsigned int th_ack;          
unsigned char th_lenres;        
unsigned char th_flag;         
USHORT th_win;              
USHORT th_sum;              
USHORT th_urp;              
} TCP_HEADER; 

typedef struct _PSD_HEADER         
{ 
unsigned long saddr;          
unsigned long daddr;          
char mbz; 
char ptcl;                 
unsigned short tcpl;          
} PSD_HEADER; 
// End Of Structure Declaration 

// Function ProtoType Declaration 
//------------------------------------------------------------------------------------------------------ 
USHORT checksum(USHORT *buffer, int size); 
int   CheckingPort(const char *RecvBuffer); 
DWORD  WINAPI PrepareSniffing(LPVOID Para); 
DWORD  WINAPI SynScan(LPVOID Para); 
BOOL  InitSocket(); 
BOOL  IsWin2K(); 
//------------------------------------------------------------------------------------------------------ 
// End Of Fucntion ProtoType Declaration 

// Main Function 
int main(int argc,char *argv[]) 
{ 
HANDLE *ThreadHandle = NULL; 
DWORD  ScanTime = 0; 
DWORD  dwThreadID; 
UINT  NumberOfPort = 0; 
UINT  OpenPort = 0; 
UINT  i = 0; 
HANDLE SniffingHandle = NULL; 

if (!IsWin2K())      // Not Win 2K Or Above OS,Then Exit 
{ 
    printf("The Program Can Only Run On WIN 2K Or Above\n");      
    return -1; 
} 

if (argc != 2)        // The Number Of Arguments Are Not Meet,Then Exit 
{ 
    printf("%s IP\n",argv[0]); 
    return -1; 
} 

pHost = argv[1];      // Store The Remote Host IP 

if (!InitSocket())      // Fail To StartUp Socket,Then Exit 
{ 
    printf("Fail To Init Socket\n"); 
    return -1; 
} 

NumberOfPort = sizeof(PortToScan) / sizeof(int);      // Number Of Port We Need To Scan 
StatusFlag = (BOOL *)malloc(sizeof(BOOL) * NumberOfPort);      // Allocate Memory To Store Every Port&#39;s Status 
if (StatusFlag == NULL)      // No Enough Memory,Then Exit 
{ 
    printf("Fail To Allocate Memory For Status Flag\n"); 
    return -1; 
} 

ThreadHandle = (HANDLE *)malloc(sizeof(HANDLE) * NumberOfPort);      // Allocate Memory To Storey Thread Handle 
if (ThreadHandle == NULL)      // No Enough Memory,Then Exit 
{ 
    printf("Fail To Allocate Memory For Thread Handle\n"); 
    goto CleanUP; 
} 

SniffingHandle = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)PrepareSniffing,NULL,0,&dwThreadID); 
if (SniffingHandle == NULL) 
{ 
    goto CleanUP; 
} 

CloseHandle(SniffingHandle); 

ScanTime = GetTickCount();      // Store The Time We Start To Scan 

// Create Threads To Scan,One Thread To Scan One Port 
for (i = 0 ; i < NumberOfPort ; i++) 
{ 
    StatusFlag = FALSE;      // Set The Port Status To False, Meaning The Port Is Close 
    ThreadHandle = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)SynScan,(LPVOID)PortToScan,0,&dwThreadID); 
} 

printf("Scanning......\r"); 
WaitForMultipleObjects(NumberOfPort,ThreadHandle,TRUE, INFINITE);      // Wait For All Threads To Exit 
Sleep(500);      // Wait 0.5 Second BeforeThe Sniffing Thread Exit.You May Increase The Value In Slow Network Connection 

printf("Scan Complete In %d Seconds.The Result: \n\n",(GetTickCount() - ScanTime) / 1000);      // How Long The Scan Takes 

// Display The Scan Reslut 
for (i = 0 ; i < NumberOfPort ; i++) 
{ 
    if (StatusFlag)      // StatusFlag == TRUE Means The Port Is Open 
    { 
      printf("The TCP Port %-5d Is Open\n",PortToScan); 
      OpenPort++; 
    } 
    else      // The Port Is Close 
    { 
      printf("The TCP Port %-5d Is Closed\n",PortToScan); 
    } 
    CloseHandle(ThreadHandle);      // Don&#39;t Forget To Close The Thread Handle 
} 

// Display Some Statistics 
printf("\n%d Ports Scanned. %d Ports Open And %d Ports Close\n",NumberOfPort,OpenPort,NumberOfPort - OpenPort);      

// Clean EveryThing,The Order Doesn&#39;t Matter 
CleanUP: 
if (SnifferSocket != INVALID_SOCKET) 
{ 
    closesocket(SnifferSocket); 
} 
WSACleanup(); 
if (StatusFlag != NULL) 
{ 
    free(StatusFlag);      // Free The Ram,We Don&#39;t Want Memory Leak 
} 
if (ThreadHandle != NULL) 
{ 
    free(ThreadHandle);      // Free The Ram,We Don&#39;t Want Memory Leak 
} 
return 0; 
}// End Of Main Method 

//------------------------------------------------------------------------------------ 
// Purpose: To Calculate The TCP Checksum 
// Return Type: USHORT 
// Parameters:  
//        In: USHORT *Buffer  --> The Buffer To Be Calcuated The Checksum 
//        In: int   size    --> The Length Of The Buffer 
// I Won&#39;t Comment This 
//------------------------------------------------------------------------------------ 
USHORT checksum(USHORT *buffer, int size) 
{ 
unsigned long cksum = 0; 
while (size > 1) 
{ 
    cksum += *buffer++; 
    size -= sizeof(USHORT); 
} 
if (size) 
{ 
    cksum += *(UCHAR*)buffer; 
} 
cksum = (cksum >> 16) + (cksum & 0xffff); 
cksum += (cksum >>16); 
return (USHORT)(~cksum); 
}// End Of checksum() 

//------------------------------------------------------------------------------------ 
// Purpose: To Check Whether A Port Is Open 
// Return Type: int 
// Parameters:  
//        In: const DWORD DestIP     --> Destination IP 
//        In: const char *RecvBuffer  --> Buffer Received 
//------------------------------------------------------------------------------------ 
int CheckingPort(const char *RecvBuffer) 
{ 
IP_HEADER     *ip_hdr; 
TCP_HEADER    *tcp_hdr; 
unsigned short  ip_hdr_len; 

ip_hdr = (IP_HEADER *)RecvBuffer;      // Get The IP Header 
ip_hdr_len = sizeof(unsigned long) * (ip_hdr->h_lenver & 0xf);      // Get The IP Header Length 
tcp_hdr = (TCP_HEADER*)(RecvBuffer + ip_hdr_len);      // Get The TCP Header 

if (ip_hdr->sourceIP != inet_addr(pHost))      // Is The Buffer Coming From The Same Host We Scan,If Not,Then Ignore This Received Buffer 
{ 
    return -1;      // The Result Is Not What We Expect 
} 

// Check All The Ports 
for (UINT i = 0 ; i < sizeof(PortToScan) / sizeof(int) ; i++) 
{ 
    if (tcp_hdr->th_flag == 20)      // No Service Exists, No Port Is Open Then 
    { 
      return 0;      // Found None 
    } 

    if (tcp_hdr->th_flag == 18 && tcp_hdr->th_sport == htons(PortToScan))      // We Get The Open Port 
    { 
      StatusFlag = TRUE;      // Set StatusFlag To Indicate The Corresponding Port Is Open 
      return 1;      // We Found One 
    } 
} 
return 0;      // Found No Port Is Open 
} 
// End Of CheckingPort() 

//------------------------------------------------------------------------------------ 
// Purpose: To Create Sniffing Thread 
// Return Type: BOOLEAN 
// Parameters:  NULL 
// A Very Simple Routine,No Need To Comment In Detail 
//------------------------------------------------------------------------------------ 
DWORD WINAPI PrepareSniffing(LPVOID Para) 
{ 
struct hostent  *PHostent; 
char         RecvBuffer[65535] = {0}; 
int          iRet; 
struct sockaddr_in Source; 

SnifferSocket = socket(AF_INET , SOCK_RAW , IPPROTO_RAW);      // Create The Socket 
if (SnifferSocket == SOCKET_ERROR)      // Fail To Create Socket, 
{ 
    return FALSE; 
} 

// Get The Local Host IP 
char LocalHost[256]; 
if (gethostname(LocalHost, sizeof(LocalHost)) == SOCKET_ERROR)      
{ 
    closesocket(SnifferSocket); 
    return FALSE; 
} 

if((PHostent = gethostbyname(LocalHost)) == NULL) 
{ 
    closesocket(SnifferSocket); 
    return FALSE; 
} 

memcpy(&Source.sin_addr.S_un.S_addr, PHostent->h_addr_list[0], PHostent->h_length); 
Source.sin_family = AF_INET; 
Source.sin_port = htons(0); 

// Bind On That Local IP 
iRet = bind(SnifferSocket, (PSOCKADDR)&Source, sizeof(Source)); 
if (iRet == SOCKET_ERROR) 
{ 
    closesocket(SnifferSocket); 
    return FALSE; 
} 

DWORD dwBufferLen[10] = {0}; 
DWORD dwBufferInLen = 1 ; 
DWORD dwBytesReturned = 0 ; 
iRet = WSAIoctl(SnifferSocket, SIO_RCVALL, &dwBufferInLen, sizeof(dwBufferInLen), 
            &dwBufferLen, sizeof(dwBufferLen), &dwBytesReturned, NULL, NULL); 
if (iRet == SOCKET_ERROR) 
{ 
    closesocket(SnifferSocket); 
    return FALSE; 
} 
while(TRUE)      // Loop Forever 
{ 
    ZeroMemory(RecvBuffer,sizeof(RecvBuffer)); 

    // Receive The Incoming Packet 
    if (recv(SnifferSocket, RecvBuffer, sizeof(RecvBuffer), 0) <= 0)      // Blocking Socket Problem? I Know,But I Am Too Lazy.It&#39;s Your Task To Solve It Yourself. 
    { 
      break; 
    } 

    // Check The Port 
    CheckingPort(RecvBuffer); 
} 
return TRUE; 
} 
// End Of PrepareSniffing() 

//------------------------------------------------------------------------------------ 
// Purpose: To Scan The Port 
// Return Type: DWORD 
// Parameters:  
//        1.In: LPVOID Para -> The Port To Scan 
//------------------------------------------------------------------------------------ 
DWORD WINAPI SynScan(LPVOID Para) 
{ 
int nPort = (int)Para;      // Get The Port To Scan 

// Local Variables Declaration 
SOCKET RawSocket = INVALID_SOCKET; 
int          nDataSize; 
DWORD        dwSeq; 
struct hostent  *PHostent; 
IP_HEADER      ip_header; 
TCP_HEADER     tcp_header; 
PSD_HEADER     psd_header; 
char         SendBuffer[256]={0}; 
char         RecvBuffer[65535]={0}; 
struct        sockaddr_in Source, Dest; 
BOOL         Value = TRUE; 
char         LocalHost[256]; 
// End Local Variables Declaration 

dwSeq = 0x19831018 + nPort;   // Set A Sequence 
RawSocket = socket(AF_INET , SOCK_RAW , IPPROTO_RAW);      // Create The Socket 
if (RawSocket == SOCKET_ERROR)      // Fail To Create Socket 
{ 
    goto CleanUP; 
} 

// Set This,So We Can Send Customer-Defined Packet 
Value = TRUE; 
if (setsockopt(RawSocket, IPPROTO_IP, IP_HDRINCL, (char *)&Value, sizeof(Value)) == SOCKET_ERROR) 
{ 
    goto CleanUP; 
} 

// Get The Local Host IP 
if (gethostname(LocalHost, sizeof(LocalHost)-1) == SOCKET_ERROR) 
{ 
    goto CleanUP; 
} 
if ((PHostent = gethostbyname(LocalHost)) == NULL) 
{ 
    goto CleanUP; 
} 
memcpy(&Source.sin_addr.S_un.S_addr, PHostent->h_addr_list[0], PHostent->h_length); 

// Fill The Destination Socket Structure 
memset(&Dest, 0, sizeof(Dest)); 
Dest.sin_family = AF_INET; 
Dest.sin_port = htons(nPort); 
if ((Dest.sin_addr.s_addr = inet_addr(pHost)) == INADDR_NONE) 
{ 
    if ((PHostent = gethostbyname(pHost)) != NULL) 
    { 
      memcpy(&(Dest.sin_addr), PHostent->h_addr_list[0], PHostent->h_length); 
      Dest.sin_family = PHostent->h_addrtype; 
    } 
    else 
    { 
      goto CleanUP; 
    } 
} 

// Fill The IP Header 
ip_header.h_lenver=(4<<4 | sizeof(ip_header)/sizeof(unsigned long)); 
ip_header.total_len = htons(sizeof(IP_HEADER)+sizeof(TCP_HEADER)); 
ip_header.ident = 1; 
ip_header.frag_and_flags = 0; 
ip_header.ttl = 120; 
ip_header.proto = IPPROTO_TCP; 
ip_header.checksum = 0; 
ip_header.sourceIP = Source.sin_addr.s_addr; 
ip_header.destIP = Dest.sin_addr.s_addr; 

// Fill The TCP Header 
tcp_header.th_sport = htons(0); 
tcp_header.th_dport = htons(nPort); // Dest Port 
tcp_header.th_seq = htonl(dwSeq); // Syn Sequence 
tcp_header.th_ack = 0; 
tcp_header.th_lenres = (sizeof(TCP_HEADER)/4<<4|0); 
tcp_header.th_flag = 2; 
tcp_header.th_win = htons(16384); 
tcp_header.th_urp = 0; 
tcp_header.th_sum = 0; 

psd_header.saddr = ip_header.sourceIP; 
psd_header.daddr = ip_header.destIP; 
psd_header.mbz = 0; 
psd_header.ptcl = IPPROTO_TCP; 
psd_header.tcpl = htons(sizeof(tcp_header)); 

memcpy(SendBuffer, &psd_header, sizeof(psd_header)); 
memcpy(SendBuffer+sizeof(psd_header), &tcp_header, sizeof(tcp_header)); 
tcp_header.th_sum = checksum((USHORT *)SendBuffer, sizeof(psd_header)+sizeof(tcp_header)); 

memcpy(SendBuffer, &ip_header, sizeof(ip_header)); 
memcpy(SendBuffer+sizeof(ip_header), &tcp_header, sizeof(tcp_header)); 
memset(SendBuffer+sizeof(ip_header)+sizeof(tcp_header), 0, 4); 
nDataSize = sizeof(ip_header)+sizeof(tcp_header); 
ip_header.checksum = checksum((USHORT *)SendBuffer, sizeof(ip_header)); 

memcpy(SendBuffer, &ip_header, sizeof(ip_header)); 

// Send The Packet 
if (sendto(RawSocket, SendBuffer, nDataSize, 0, (struct sockaddr*)&Dest, sizeof(Dest)) == SOCKET_ERROR) 
{ 
    goto CleanUP; 
} 

CleanUP: 
if(RawSocket != INVALID_SOCKET) 
{ 
    closesocket(RawSocket); 
} 
return 0; 
}// End Of SynScan() 

//------------------------------------------------------------------------- 
// Purpose: To Initize Socket 
// Return Type: Boolean 
// Parameters:  NULL 
// This Is Too Simple,I Won&#39;t Comment It 
//------------------------------------------------------------------------- 
BOOL InitSocket() 
{ 
WSADATA data; 
return (WSAStartup(MAKEWORD(2,2), &data) == 0); 
}// End Of InitSocket() 

//------------------------------------------------------------------------- 
// Purpose: To Check The OS Version 
// Return Type: Boolean 
// Parameters:  NULL 
// This Is Too Simple,I Won&#39;t Comment It 
//------------------------------------------------------------------------- 
BOOL IsWin2K() 
{ 
OSVERSIONINFO OSVersionInfo; 
OSVersionInfo.dwOSVersionInfoSize = sizeof (OSVERSIONINFO); 
if (GetVersionEx(&OSVersionInfo)) 
{ 
    return ((OSVersionInfo.dwPlatformId == VER_PLATFORM_WIN32_NT) && (OSVersionInfo.dwMajorVersion == 5)); 
} 
return FALSE; 
} 
// End Of IsWin2K() 
// End Of File