#ifndef CHAIN_TRACER_H
#define CHAIN_TRACER_H

#include "types.h"
#include <windows.h>

#define MAX_CHAIN_DEPTH 5

/*
 * Trace a hook chain starting from a hooked function.
 * Follows unconditional JMP / PUSH+RET / MOV reg,imm+JMP reg / CALL [mem]
 * indirections through memory, disassembling each step with Zydis.
 * Stops at conditional jumps, unsupported patterns, unreadable memory or
 * MAX_CHAIN_DEPTH.
 *
 * process:    Open handle to target process (PROCESS_VM_READ)
 * start_addr: Address of the first hook instruction
 * is_64bit:   True if the target process is 64-bit
 * chain:      Output array of chain_step_t (at least MAX_CHAIN_DEPTH entries)
 * chain_len:  Output: number of steps traced (0 if the first read failed)
 * Returns:    always 0 (kept for source compatibility); check chain_len
 *             instead — 0 means no chain could be traced.
 */
int chain_trace(HANDLE process, uintptr_t start_addr, bool is_64bit,
                chain_step_t* chain, int* chain_len);

#endif /* CHAIN_TRACER_H */
