#pragma once

#include <stdio.h>
#include <stdint.h>

typedef uint8_t u8;
typedef int32_t i32;
typedef uint32_t u32;
typedef int64_t i64;
typedef float f32;
typedef double f64;

#define DATA_LOG_FILE_PATH "data_log.txt"

#define EXPORT __declspec(dllexport)
#define NAKED __declspec(naked)
#define STDCALL __stdcall

#define PUSH_REGISTERS() __asm {\
    __asm push eax\
    __asm push ebx\
    __asm push ecx\
    __asm push edx\
    __asm push esi\
    __asm push edi}

#define POP_REGISTERS() __asm {\
    __asm pop edi\
    __asm pop esi\
    __asm pop edx\
    __asm pop ecx\
    __asm pop ebx\
    __asm pop eax}

void logf(const char* format, ...);

void MOD_init();
void MOD_deinit();

#define DBG_WAIT_FOR_ATTACH
