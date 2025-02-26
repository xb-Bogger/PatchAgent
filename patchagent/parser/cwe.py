from enum import StrEnum


class CWE(StrEnum):
    UNKNOWN = "unknown"

    ILL = "ill"
    ABORT = "abort"
    Null_dereference = "null dereference"
    Segv_on_unknown_address = "segv on unknown address"
    Heap_buffer_overflow = "heap buffer overflow"
    Stack_buffer_overflow = "stack buffer overflow"
    Stack_buffer_underflow = "stack buffer underflow"
    Dynamic_stack_buffer_overflow = "dynamic stack buffer overflow"
    Global_buffer_overflow = "global buffer overflow"
    Container_overflow = "container overflow"
    Negative_size_param = "negative size param"
    Memcpy_param_overlap = "memcpy param overlap"
    Index_out_of_bounds = "index out of bounds"
    Stack_overflow = "stack overflow"
    Stack_use_after_return = "stack use after return"
    Stack_use_after_scope = "stack use after scope"
    Heap_double_free = "heap double free"
    Heap_use_after_free = "heap use after free"
    Invalid_free = "invalid free"
    Bad_free = "bad free"
    Bad_cast = "bad cast"
    Memory_Leak = "memory leak"
    Out_of_memory = "out of memory"

    File_path_traversal = "file path traversal"
    LDAP_injection = "ldap injection"
    Naming_context_lookup = "naming context lookup"
    OS_command_injection = "os command injection"
    Reflective_call = "reflective call"
    Remote_code_execution = "remote code execution"
    Regular_expression_injection = "regular expression injection"
    Script_engine_injection = "script engine injection"
    Server_side_request_forgery = "server side request forgery"
    SQL_injection = "sql injection"
    XPath_injection = "xpath injection"


CWE_DESCRIPTIONS = {
    CWE.UNKNOWN: "The nature of the vulnerability is unknown or unspecified.",
    CWE.ILL: "The program encountered an illegal instruction, indicating a hardware or software issue.",
    CWE.ABORT: "The program was terminated due to an abort signal, indicating a critical error.",
    CWE.Null_dereference: "The program attempts to dereference a null pointer, causing a segmentation fault or crash.",
    CWE.Segv_on_unknown_address: "The program attempted to access an invalid or unallocated memory address, leading to a segmentation fault.",
    CWE.Heap_buffer_overflow: "The program tried to access a heap object outside of its allocated memory, causing potential memory corruption or crashes.",
    CWE.Stack_buffer_overflow: "A function writes more data to a local stack variable than it can hold, overwriting adjacent memory and potentially leading to execution hijacking.",
    CWE.Stack_buffer_underflow: "A program attempts to read data before the beginning of a stack buffer, leading to unintended behavior.",
    CWE.Dynamic_stack_buffer_overflow: "A dynamically allocated stack buffer is overflowed, leading to potential memory corruption or execution hijacking.",
    CWE.Global_buffer_overflow: "A buffer overflow occurs in globally allocated memory, leading to memory corruption or crashes.",
    CWE.Container_overflow: "A data structure, such as a vector or list, is accessed beyond its allocated memory, causing memory corruption or unexpected behavior.",
    CWE.Negative_size_param: "A function receives a negative size parameter, leading to unexpected behavior or memory allocation errors.",
    CWE.Memcpy_param_overlap: "The source and destination buffers of a memory copy operation overlap, causing data corruption.",
    CWE.Index_out_of_bounds: "An array or container is accessed using an index that is out of its valid range, leading to memory corruption or crashes.",
    CWE.Stack_overflow: "Excessive function calls lead to stack exhaustion, causing the program to crash or behave unpredictably.",
    CWE.Stack_use_after_return: "A function accesses stack memory after returning, leading to use-after-free vulnerabilities.",
    CWE.Stack_use_after_scope: "A program accesses stack memory that has gone out of scope, leading to undefined behavior or crashes.",
    CWE.Heap_double_free: "A heap-allocated memory block is freed twice, potentially causing memory corruption or security vulnerabilities.",
    CWE.Heap_use_after_free: "Memory is accessed after it has been freed, leading to undefined behavior and security risks.",
    CWE.Invalid_free: "A program attempts to free a memory block that was not dynamically allocated, causing undefined behavior or crashes.",
    CWE.Bad_free: "A program incorrectly deallocates memory, leading to potential memory corruption or instability.",
    CWE.Bad_cast: "An invalid type conversion occurs, leading to memory corruption, crashes, or security vulnerabilities.",
    CWE.Memory_Leak: "A program fails to free allocated memory, leading to resource exhaustion and degraded system performance over time.",
}

CWE_REPAIR_ADVICE = {
    **dict.fromkeys(
        [CWE.ABORT],
        (
            "1. Investigate the cause of the abort signal to identify the root cause of the error.\n"
            "2. Review the program's error handling mechanisms to ensure critical errors are handled appropriately.\n"
        ),
    ),
    **dict.fromkeys(
        [CWE.ILL],
        (
            "1. Investigate the cause of the illegal instruction to identify the source of the error.\n"
            "2. Check for hardware or software issues that may be causing the illegal instruction.\n"
        ),
    ),
    **dict.fromkeys(
        [CWE.Heap_buffer_overflow, CWE.Stack_buffer_overflow, CWE.Dynamic_stack_buffer_overflow, CWE.Global_buffer_overflow, CWE.Container_overflow, CWE.Index_out_of_bounds],
        (
            "1. If overflow is unavoidable, allocate a sufficiently large buffer during initialization.\n"
            "2. Add explicit bounds checking before accessing arrays or buffers to prevent overflows.\n"
            "3. Replace unsafe functions like memcpy, strcpy, strcat, and sprintf with safer alternatives such as strncpy, strncat, and snprintf.\n"
            "4. Check for integer overflows in size calculations that could cause improper memory allocations.\n"
        ),
    ),
    **dict.fromkeys(
        [CWE.Stack_buffer_underflow],
        (
            "1. Ensure that stack buffers are properly initialized before reading data from them.\n"
            "2. Implement bounds checking to prevent underflow conditions.\n"
            "3. Use safer string manipulation functions like strncpy and strncat to avoid buffer underflows."
        ),
    ),
    **dict.fromkeys(
        [CWE.Null_dereference, CWE.Segv_on_unknown_address],
        (
            "1. Ensure all pointers are initialized before use to prevent null dereferences.\n"
            "2. Validate pointer values before dereferencing them.\n"
            "3. Implement default values for pointers to reduce the risk of unintended NULL dereferences."
        ),
    ),
    **dict.fromkeys(
        [CWE.Stack_use_after_return, CWE.Stack_use_after_scope],
        (
            "1. Avoid returning addresses of local variables from functions, as stack memory is deallocated after return.\n"
            "2. If persistent storage is needed, use heap-allocated memory instead of local stack memory.\n"
            "3. Check the lifetime of variables to ensure they are not accessed after they go out of scope."
        ),
    ),
    **dict.fromkeys(
        [CWE.Heap_use_after_free, CWE.Heap_double_free],
        (
            "1. Set pointers to NULL immediately after freeing them to prevent accidental reuse.\n"
            "2. Ensure that each allocated memory block is freed only once.\n"
            "3. Track memory allocations and deallocations systematically to prevent use-after-free conditions.\n"
            "4. Consider swap the order of freeing memory and accessing it."
        ),
    ),
    **dict.fromkeys(
        [CWE.Bad_free, CWE.Invalid_free],
        (
            "1. Ensure that only dynamically allocated memory is freed.\n"
            "2. Avoid freeing memory that was not allocated using malloc or similar functions.\n"
            "3. Verify pointer values before attempting to free them."
        ),
    ),
    **dict.fromkeys(
        [CWE.Bad_cast],
        (
            "1. Verify type compatibility before performing a type cast operation.\n"
            "2. Avoid casting pointers between incompatible types to prevent undefined behavior.\n"
            "3. Use safer type conversion functions like static_cast or dynamic_cast where possible."
        ),
    ),
    **dict.fromkeys(
        [CWE.Memory_Leak],
        (
            "1. Ensure that every memory allocation has a corresponding deallocation.\n"
            "2. Track allocated memory systematically to avoid leaks.\n"
            "3. Avoid unnecessary memory allocations by reusing buffers where possible."
        ),
    ),
    **dict.fromkeys(
        [CWE.Negative_size_param],
        (
            "1. Validate all size parameters before passing them to memory allocation functions.\n"
            "2. Ensure that buffer sizes and loop limits are always positive values.\n"
            "3. Use unsigned integer types to store sizes to prevent negative values."
        ),
    ),
    **dict.fromkeys(
        [CWE.Memcpy_param_overlap],
        (
            "1. Ensure that the source and destination buffers do not overlap in memcpy operations.\n"
            "2. If overlapping memory regions must be copied, use memmove instead of memcpy.\n"
            "3. Validate memory regions before performing copy operations."
        ),
    ),
    **dict.fromkeys(
        [CWE.Stack_overflow],
        (
            "1. Avoid deep recursion by implementing iterative solutions where possible.\n"
            "2. Increase the stack size if necessary to accommodate recursion.\n"
            "3. Reduce function call depth by refactoring complex recursive functions."
        ),
    ),
    **dict.fromkeys(
        [CWE.UNKNOWN],
        (
            "1. Review the code logic and memory operations to identify potential corruption.\n"
            "2. Check for uninitialized variables or unintended pointer accesses.\n"
            "3. Implement defensive programming techniques to validate all memory accesses."
        ),
    ),
}
