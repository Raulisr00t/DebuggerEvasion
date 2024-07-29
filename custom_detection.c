#include <Windows.h>
#include <stdio.h>
#include <WinBase.h>
#include <winternl.h>

// Declare external assembly functions
extern PTEB getTEB(void);
extern DWORD CustomError(void);
extern PPEB getPEB(void);
extern BYTE CheckDebugger(void);

// Function to simulate running malware
BOOL RunMalware() {
    MessageBoxA(NULL, "Running Malware for encryption", "Raulisr00t", MB_ICONEXCLAMATION | MB_OK);
    return TRUE;
}

int main(void) {
    HANDLE hProcess;
    printf("[!] Getting The TEB [!]\n");
    PTEB pTEB = getTEB();
    PPEB pPEB = getPEB();

    if (pTEB == NULL) {
        printf("[-] Not found TEB Address [-]\n");
        return 1;
    }

    if (pPEB == NULL) {
        printf("[-] Not found PEB Address [-]\n");
        return 1;
    }

    printf("[+] Address of TEB: 0x%p\n", pTEB);
    printf("[+] Address of PEB: 0x%p\n", pPEB);

    BYTE debuggerDetected = CheckDebugger();
    printf("[DEBUG] CheckDebugger returned: %d\n", debuggerDetected);
    if (debuggerDetected) {
        printf("[!] Debugger Detected!\n");
        MessageBoxA(NULL, "IT's Not Malware!", "NotMalware", MB_ICONEXCLAMATION | MB_OKCANCEL);
        return EXIT_SUCCESS;
    }
    else {
        printf("[+] Debugger Not Detected!\n");
        RunMalware();
    }

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1337);
    if (hProcess == NULL) {
        DWORD lastError = GetLastError();
        DWORD customError = CustomError();

        printf("[!] Error in Opening Process: %lu\n", lastError);
        printf("[!] Custom Error Value: %lu\n", customError);

        if (customError == lastError) {
            printf("[+] Your Custom Error asm is working man))\n");
            return EXIT_SUCCESS;
        }
        else {
            printf("[-] Write again plz ...\n");
            return EXIT_FAILURE;
        }
    }

    // Add any additional logic here if necessary

    return 0;
}
