/*
gcc -o antiVirus.exe antiVirus.c
antiVirus.exe L:\test L:\cleaned_files
*/
#include <stdio.h>
#include <stdlib.h>     // For malloc, free
#include <string.h>     // For strncmp, strcpy_s, etc.
#include <windows.h>    // For PE structs and FindFirstFile/FindNextFile
#include <stdarg.h>     // For va_list (logging)

// -----------------------------------------------------------------
// === KEY CONSTANTS FROM YOUR ANALYSIS ===
// -----------------------------------------------------------------
// Offset from virus_stub start to original_entry_point_stub
#define OFFSET_TO_OEP_STORAGE 0x9F 
// The name of the section added by virus
#define VIRUS_SECTION_NAME ".infect"
// -----------------------------------------------------------------

/**
 *  ScannerState
 *  struct to hold the scanner's state 
 */
typedef struct {
    int totalScanned;
    int totalInfected;
    int totalCleaned;
    FILE* logFile;
    char outputDir[MAX_PATH];
} ScannerState;

/**
    logging function (prints to both console and log file).
 */
void logMessage(ScannerState* state, const char* format, ...) {
    char buffer[2048];
    va_list args;
    va_start(args, format);
    // Format the string
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    // Print to console
    printf("%s", buffer);

    // Write to log file
    if (state->logFile) {
        fprintf(state->logFile, "%s", buffer);
        fflush(state->logFile); // Flush buffer to ensure data is written
    }
}

/*
    Converts a RVA to a file offset
 */
DWORD RvaToOffset(PIMAGE_NT_HEADERS ntHeaders, DWORD rva) {
    // Get the first section header
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    int numSections = ntHeaders->FileHeader.NumberOfSections;
    int i;

    // Loop through all sections
    for (i = 0; i < numSections; i++) {
        // Check if the RVA is within this section's VA range
        if (rva >= sectionHeader[i].VirtualAddress &&
            rva < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
            // Calculate and return the file offset
            return (rva - sectionHeader[i].VirtualAddress) + sectionHeader[i].PointerToRawData;
        }
    }
    // RVA not found in any section
    return 0;
}

/**
 * Performs the disinfection logic on the file buffer.
 * 1 (success), 0 (false) 
 */
int disinfect(ScannerState* state, BYTE* pFileBuffer, PIMAGE_NT_HEADERS ntHeaders, PIMAGE_SECTION_HEADER infectedSection) {
    // Get the RVA of the virus stub (.infect Entry Point)
    DWORD infected_EP_RVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;

    // Calculate the RVA of the *saved* OEP
    //    We use the 0x9F constant we found from the .lst file
    DWORD rvaOfOEPStorage = infected_EP_RVA + OFFSET_TO_OEP_STORAGE;

    // Convert the OEP storage RVA to a file offset
    DWORD fileOffset_OEP = RvaToOffset(ntHeaders, rvaOfOEPStorage);
    if (fileOffset_OEP == 0) {
        logMessage(state, "  [ERROR] Could not find offset to recover OEP.\n");
        return 0; // false
    }

    // Read the 4-byte original OEP from the buffer
    DWORD original_OEP = *(DWORD*)(pFileBuffer + fileOffset_OEP);

    // Restore the original OEP in the PE header
    ntHeaders->OptionalHeader.AddressOfEntryPoint = original_OEP;
    logMessage(state, "  [INFO] Original OEP restored: 0x%X\n", original_OEP);

    // Decrease the section count in the file header
    ntHeaders->FileHeader.NumberOfSections--;

    // Erase (zero-out) the infected section's header entry
    memset(infectedSection, 0, sizeof(IMAGE_SECTION_HEADER));

    return 1; 
}

/**
    Processes a single file: read, parse, detect, and disinfect
 */
void processFile(ScannerState* state, const char* filePath) {
    state->totalScanned++;
    logMessage(state, "Scanning: %s\n", filePath);

    FILE* file = NULL;
    BYTE* pFileBuffer = NULL;
    long fileSize = 0;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_SECTION_HEADER sectionHeader, infectedSection = NULL;
    int i, infectedSectionIndex = -1;
    DWORD infected_EP_RVA;
    
    // 1. Read the entire file into a memory buffer
    if (fopen_s(&file, filePath, "rb") != 0) {
        logMessage(state, "  [ERROR] Cannot open file.\n");
        return;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory for the file
    pFileBuffer = (BYTE*)malloc(fileSize);
    if (pFileBuffer == NULL) {
        logMessage(state, "  [ERROR] Cannot allocate memory.\n");
        fclose(file);
        return;
    }

    // Read file content into the buffer
    if (fread(pFileBuffer, 1, fileSize, file) != fileSize) {
        logMessage(state, "  [ERROR] Cannot read file.\n");
        fclose(file);
        free(pFileBuffer);
        return;
    }
    fclose(file); // Close the file handle

    // 2. Parse the PE structure
    // Check DOS "MZ" signature
    dosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        goto cleanup; // Not a valid MZ file
    }

    // Check NT "PE" signature
    ntHeaders = (PIMAGE_NT_HEADERS)(pFileBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        goto cleanup; // Not a valid PE file
    }

    // Check for 32-bit (as required by the assignment)
    if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        goto cleanup; // Not a 32-bit PE file
    }

    // 3. Detection Logic
    sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    infected_EP_RVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;

    // Loop through all sections
    for (i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        // Signature 1: Check section name
        if (strncmp((char*)sectionHeader[i].Name, VIRUS_SECTION_NAME, 8) == 0) {
            // Signature 2: Check if Entry Point is within this section
            if (infected_EP_RVA >= sectionHeader[i].VirtualAddress &&
                infected_EP_RVA < (sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize)) {
                
                // Found it!
                infectedSection = &sectionHeader[i];
                infectedSectionIndex = i;
                break;
            }
        }
    }

    // 4. Handle infection if found
    if (infectedSection) {
        state->totalInfected++;
        logMessage(state, "  [INFECTED] File is infected! EntryPoint: 0x%X\n", infected_EP_RVA);

        // 5. Attempt to disinfect
        if (disinfect(state, pFileBuffer, ntHeaders, infectedSection)) {
            state->totalCleaned++;

            // 6. Create the path for the new "clean" file
            char cleanPath[MAX_PATH];
            const char* fileName = strrchr(filePath, '\\'); // Find the last '\'
            if (fileName == NULL) {
                fileName = filePath; // No '\', use the whole path
            } else {
                fileName++; // Skip the '\'
            }

            // Build the full output path
            sprintf_s(cleanPath, MAX_PATH, "%s\\%s", state->outputDir, fileName);

            // 7. Truncate and save the clean file
            if (infectedSectionIndex == 0) {
                logMessage(state, "  [ERROR] Virus section is the first section. Cannot truncate.\n");
                state->totalCleaned--; // Revert counter
                goto cleanup;
            }
            
            // Find the section *before* the infected one
            PIMAGE_SECTION_HEADER lastGoodSection = &sectionHeader[infectedSectionIndex - 1];
            // New file size = offset of last good section + its raw size
            DWORD newFileSize = lastGoodSection->PointerToRawData + lastGoodSection->SizeOfRawData;

            // Write the modified buffer to the new file
            FILE* outFile = NULL;
            if (fopen_s(&outFile, cleanPath, "wb") == 0) {
                // Write only up to the new file size
                fwrite(pFileBuffer, 1, newFileSize, outFile);
                fclose(outFile);
                logMessage(state, "  [CLEANED] Clean file saved to: %s\n", cleanPath);
            } else {
                logMessage(state, "  [ERROR] Could not write clean file: %s\n", cleanPath);
                state->totalCleaned--; // Revert counter
            }
        } else {
            logMessage(state, "  [ERROR] Disinfection failed.\n");
        }
    }

cleanup:
    // Free the memory buffer allocated for the file
    free(pFileBuffer);
}

/**
    Recursively scans a directory using Win32 API.
 */
void scanDirectory(ScannerState* state, char* dirPath) {
    char searchPath[MAX_PATH];
    WIN32_FIND_DATAA findData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char fullPath[MAX_PATH];
    char originalPath[MAX_PATH]; // Store the original path for recursion

    // Create the search path (e.g., L:\test\*)
    sprintf_s(searchPath, MAX_PATH, "%s\\*", dirPath);
    
    // Save the current path
    strcpy_s(originalPath, MAX_PATH, dirPath);

    // Start finding files
    hFind = FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        logMessage(state, "[FATAL ERROR] Cannot access directory: %s\n", dirPath);
        return;
    }

    // Loop through all entries
    do {
        // Skip "." and ".." directories
        if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0) {
            continue;
        }

        // Build the full path for the found item
        sprintf_s(fullPath, MAX_PATH, "%s\\%s", originalPath, findData.cFileName);

        // If it's a directory, recurse
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scanDirectory(state, fullPath);
        }
        // If it's a file
        else {
            // Check for .exe or .dll extension
            const char* ext = strrchr(findData.cFileName, '.');
            if (ext != NULL) {
                // _stricmp is case-insensitive string compare
                if (_stricmp(ext, ".exe") == 0 || _stricmp(ext, ".dll") == 0) {
                    // Process this file
                    processFile(state, fullPath);
                }
            }
        }
    } while (FindNextFileA(hFind, &findData) != 0); 

    FindClose(hFind); // Clean up the find handle
}

/*
 final summary report
 */
void printReport(ScannerState* state) {
    logMessage(state, "\n=====================\n");
    logMessage(state, "   SCAN REPORT\n");
    logMessage(state, "=====================\n");
    logMessage(state, "Total files scanned: %d\n", state->totalScanned);
    logMessage(state, "Infected files found:  %d\n", state->totalInfected);
    logMessage(state, "Files cleaned:       %d\n", state->totalCleaned);
    logMessage(state, "=====================\n");
}


int main(int argc, char* argv[]) {
    // Check INPUT correct command-line arguments
    if (argc != 3) {
        printf("Antivirus Scanner (Assignment 4) - C Version\n");
        printf("Usage: Antivirus.exe <ScanDirectory> <CleanDirectory>\n");
        printf("Example: Antivirus.exe L:\\test L:\\cleaned_files\n");
        return 1;
    }

    char scanDir[MAX_PATH];
    char outDir[MAX_PATH];
    char logPath[MAX_PATH] = "scan_report.txt";     // Log file 

    // Copy arguments to local variables
    strcpy_s(scanDir, MAX_PATH, argv[1]);
    strcpy_s(outDir, MAX_PATH, argv[2]);

    // Ensure the output directory exists
    CreateDirectoryA(outDir, NULL);     // nothing if it already exists

    // Initialize the scanner state
    ScannerState state = { 0 };         // Zero-initializes all members
    strcpy_s(state.outputDir, MAX_PATH, outDir);

    // Open the log file
    if (fopen_s(&state.logFile, logPath, "w") != 0) {
        fprintf(stderr, "Cannot open log file: %s\n", logPath);
        return 1;
    }

    // Log the initial setup
    logMessage(&state, "Initializing Antivirus Engine (C Version)...\n");
    logMessage(&state, "Scanning: %s\n", scanDir);
    logMessage(&state, "Clean files output: %s\n", state.outputDir);
    logMessage(&state, "Log file: %s\n\n", logPath);

    // Start the scan
    logMessage(&state, "--- Starting scan of: %s ---\n\n", scanDir);
    scanDirectory(&state, scanDir);
    logMessage(&state, "\n--- Scan complete ---\n");

    // Print the final report
    printReport(&state);

    // Clean up
    if (state.logFile) {
        fclose(state.logFile);
    }

    printf("\nDone. Check 'scan_report.txt' for details.\n");
    return 0;
}