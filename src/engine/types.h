#ifndef HOOKSCAN_TYPES_H
#define HOOKSCAN_TYPES_H

#include <stdint.h>
#include <stdbool.h>

/* Hook types */
typedef enum {
    HOOK_IAT,
    HOOK_INLINE,
    HOOK_EAT
} hook_type_t;

/* Single step in a hook chain (for tracing JMP targets) */
typedef struct {
    uintptr_t address;        /* Address of the instruction at this step */
    uint8_t    bytes[16];     /* Raw bytes of the instruction */
    int        byte_count;    /* Number of valid bytes in the buffer */
    char       disasm[128];   /* Zydis text disassembly */
} chain_step_t;

/* Detected hook entry */
typedef struct {
    char           module_name[64];
    char           function_name[128];
    hook_type_t    type;
    uintptr_t      original_addr;   /* Expected (on-disk) address */
    uintptr_t      current_addr;    /* Actual (in-memory) address */
    uint8_t        original_bytes[16];
    int            original_byte_count;
    uint8_t        hooked_bytes[16];
    int            hooked_byte_count;
    chain_step_t*  chain;           /* Hook chain steps (array, chain_depth entries) */
    int            chain_depth;
    bool           restorable;      /* false if packed DLL or on-disk bytes unavailable */
} hook_entry_t;

/* Scan report for a single process */
typedef struct {
    uint32_t      pid;
    char          process_name[64];
    hook_entry_t* hooks;            /* Array of detected hooks */
    int           hook_count;
    uint64_t      scan_time_ms;     /* Time taken for the scan */
    int           modules_scanned;  /* Number of DLLs scanned */
    int           error_code;       /* 0 = success, non-zero = engine error */
    char          error_msg[128];   /* Human-readable error if error_code != 0 */
} hook_report_t;

/* Module info (loaded DLL in a process) */
typedef struct {
    char       name[64];
    char       path[260];
    uintptr_t  base_addr;      /* Loaded base address in target process */
    uint32_t   size;           /* Size of the loaded image */
    bool       is_wow64;       /* True if this is a 32-bit module in WoW64 */
} module_info_t;

/* Process info with module list */
typedef struct {
    uint32_t       pid;
    char           name[64];
    module_info_t* modules;
    int            module_count;
} process_info_t;

/* Scored module for triage (embeds module info + suspicion score) */
typedef struct {
    module_info_t info;           /* copied, not borrowed */
    uint8_t       suspicion_score; /* 0-100 */
} scored_module_t;

/* Recon report: module list with suspicion scores */
typedef struct {
    uint32_t         pid;
    char             process_name[64];
    scored_module_t* modules;     /* owned array, caller frees via engine_free_module_report */
    int              module_count;
    bool             is_64bit;    /* true if host process is 64-bit */
    uint64_t         recon_time_ms;
    int              error_code;  /* 0 = success, non-zero = engine error */
    char             error_msg[128];
} module_report_t;

/* Engine error codes */
#define ENGINE_OK                0
#define ENGINE_ACCESS_DENIED    -1
#define ENGINE_PROCESS_NOT_FOUND -2
#define ENGINE_READ_ERROR       -3
#define ENGINE_WRITE_ERROR      -4
#define ENGINE_PACKED_DLL       -5
#define ENGINE_NO_MEMORY        -6
#define ENGINE_SCAN_FAILED      -7

#endif /* HOOKSCAN_TYPES_H */
