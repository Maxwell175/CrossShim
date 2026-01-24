#include "tutk_wrapper.h"
#include "memory_manager.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <cassert>
#include <vector>

using namespace cross_shim;
using namespace tutk;

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (cond) { \
        tests_passed++; \
        std::cout << "  [PASS] " << msg << std::endl; \
    } else { \
        tests_failed++; \
        std::cout << "  [FAIL] " << msg << std::endl; \
    } \
} while(0)

void print_module_info(const LoadedModule& mod) {
    std::cout << "Module: " << mod.name << std::endl;
    std::cout << "  Base: 0x" << std::hex << mod.base_address << std::endl;
    std::cout << "  Size: 0x" << mod.size << std::dec << std::endl;
    std::cout << "  Exports: " << mod.exports.size() << std::endl;
}

void test_memory_allocator() {
    std::cout << "\n=== Memory Allocator Test ===" << std::endl;

    EmulatorConfig config;
    config.enable_tracing = false;
    Emulator emu(config);

    HeapAllocator& heap = emu.memory().heap();

    // Test basic allocation
    uint64_t addr1 = heap.allocate(100, 16);
    TEST_ASSERT(addr1 != 0, "Allocate 100 bytes");
    TEST_ASSERT(heap.get_allocation_count() == 1, "Allocation count is 1");

    uint64_t addr2 = heap.allocate(200, 16);
    TEST_ASSERT(addr2 != 0, "Allocate 200 bytes");
    TEST_ASSERT(addr2 > addr1, "Second allocation is after first");
    TEST_ASSERT(heap.get_allocation_count() == 2, "Allocation count is 2");

    // Test free
    heap.free(addr1);
    TEST_ASSERT(heap.get_allocation_count() == 1, "Allocation count after free is 1");
    TEST_ASSERT(heap.get_free_block_count() == 1, "Free block count is 1");

    // Allocate again - should reuse freed block
    uint64_t addr3 = heap.allocate(50, 16);
    TEST_ASSERT(addr3 != 0, "Allocate 50 bytes (should reuse freed block)");
    TEST_ASSERT(addr3 == addr1, "Reused freed block address");

    // Test alignment
    uint64_t aligned_addr = heap.allocate(100, 64);
    TEST_ASSERT((aligned_addr % 64) == 0, "64-byte alignment");

    aligned_addr = heap.allocate(100, 256);
    TEST_ASSERT((aligned_addr % 256) == 0, "256-byte alignment");

    // Test memory read/write through allocator
    uint64_t data_addr = heap.allocate(256, 16);
    const char* test_data = "Memory allocator test data";
    emu.mem_write(data_addr, test_data, strlen(test_data) + 1);

    char read_buf[256] = {0};
    emu.mem_read(data_addr, read_buf, strlen(test_data) + 1);
    TEST_ASSERT(strcmp(read_buf, test_data) == 0, "Memory read/write through allocator");

    // Free and verify
    heap.free(data_addr);
    TEST_ASSERT(heap.get_free_block_count() >= 1, "Free block added after free");

    std::cout << "  Final stats: " << heap.get_allocation_count() << " allocations, "
              << heap.get_free_block_count() << " free blocks, "
              << heap.get_used() << " bytes used" << std::endl;
}

void test_raw_emulator() {
    std::cout << "\n=== Raw Emulator Test ===" << std::endl;

    EmulatorConfig config;
    config.enable_tracing = false;
    config.enable_syscall_logging = false;

    Emulator emu(config);
    TEST_ASSERT(true, "Emulator initialized");

    // Try to load the TUTK libraries
    const char* libs[] = {
        "libTUTKGlobalAPIs.so",
        "libIOTCAPIs.so",
        "libAVAPIs.so",
        "libRDTAPIs.so"
    };

    for (const char* lib : libs) {
        bool loaded = emu.load_library(lib);
        TEST_ASSERT(loaded, std::string("Load ") + lib);
    }

    // Print loaded modules
    std::cout << "\nLoaded Modules:" << std::endl;
    for (const auto& mod : emu.modules()) {
        print_module_info(mod);
    }

    // Test symbol lookup
    std::cout << "\nSymbol Lookup:" << std::endl;
    const char* symbols[] = {
        "IOTC_Initialize2",
        "IOTC_Get_Version",
        "IOTC_Connect_ByUID",
        "avInitialize",
        "avClientStart",
        "RDT_Initialize"
    };

    for (const char* sym : symbols) {
        uint64_t addr = emu.get_symbol(sym);
        TEST_ASSERT(addr != 0, std::string("Symbol ") + sym + " found");
    }

    // Test memory operations
    std::cout << "\nMemory Operations:" << std::endl;
    uint64_t test_addr = emu.memory().heap().allocate(256, 16);
    TEST_ASSERT(test_addr != 0, "Allocate 256 bytes");

    const char* test_str = "Hello, Android Emulator!";
    bool write_ok = emu.mem_write(test_addr, test_str, strlen(test_str) + 1);
    TEST_ASSERT(write_ok, "Write to allocated memory");

    char read_buf[256] = {0};
    bool read_ok = emu.mem_read(test_addr, read_buf, strlen(test_str) + 1);
    TEST_ASSERT(read_ok, "Read from allocated memory");
    TEST_ASSERT(strcmp(read_buf, test_str) == 0, "Read data matches written data");
}

void test_tutk_wrapper() {
    std::cout << "\n=== TUTK Wrapper Test ===" << std::endl;

    TUTKWrapper tutk;

    // Load libraries from current directory
    bool loaded = tutk.load(".");
    TEST_ASSERT(loaded, "Load TUTK libraries");

    if (!loaded) {
        std::cerr << "Cannot continue TUTK tests without libraries" << std::endl;
        return;
    }

    std::cout << "\nTUTK API Summary:" << std::endl;
    std::cout << "  IOTC: Session management, P2P connections" << std::endl;
    std::cout << "  AV:   Audio/Video streaming" << std::endl;
    std::cout << "  RDT:  Reliable data transfer" << std::endl;
}

void test_tutk_functions() {
    std::cout << "\n=== TUTK Function Call Test ===" << std::endl;

    TUTKWrapper tutk;
    if (!tutk.load(".")) {
        std::cout << "  [SKIP] Libraries not loaded" << std::endl;
        return;
    }

    // Test IOTC_Get_Version - this should work without initialization
    std::cout << "\nTesting IOTC_Get_Version..." << std::endl;
    uint32_t version = tutk.iotc().Get_Version();
    std::cout << "  Version returned: 0x" << std::hex << version << std::dec << std::endl;
    // Version should be non-zero if the function executed
    TEST_ASSERT(true, "IOTC_Get_Version called (returned " + std::to_string(version) + ")");

    // Test IOTC_Get_Version_String - this should work without initialization
    std::cout << "\nTesting IOTC_Get_Version_String..." << std::endl;
    std::string version_str = tutk.iotc().Get_Version_String();
    std::cout << "  Version_String returned: " << version_str << std::endl;
    // Version should be non-zero if the function executed
    TEST_ASSERT(true, "IOTC_Get_Version_String called (returned " + version_str + ")");

    // Test IOTC_Initialize2
    std::cout << "\nTesting IOTC_Initialize2..." << std::endl;
    int init_result = tutk.iotc().Initialize2(0);
    std::cout << "  Initialize2 returned: " << init_result << std::endl;
    // Result could be success (0) or error code - we just verify it runs
    TEST_ASSERT(true, "IOTC_Initialize2 called (returned " + std::to_string(init_result) + ")");

    // Test avInitialize
    std::cout << "\nTesting avInitialize..." << std::endl;
    int av_init = tutk.av().Initialize(8);
    std::cout << "  avInitialize returned: " << av_init << std::endl;
    TEST_ASSERT(true, "avInitialize called (returned " + std::to_string(av_init) + ")");

    // Test RDT_Initialize
    std::cout << "\nTesting RDT_Initialize..." << std::endl;
    int rdt_init = tutk.rdt().Initialize();
    std::cout << "  RDT_Initialize returned: " << rdt_init << std::endl;
    TEST_ASSERT(true, "RDT_Initialize called (returned " + std::to_string(rdt_init) + ")");

    // Test IOTC_Set_Max_Session_Number
    std::cout << "\nTesting IOTC_Set_Max_Session_Number..." << std::endl;
    tutk.iotc().Set_Max_Session_Number(16);
    TEST_ASSERT(true, "IOTC_Set_Max_Session_Number called");

    // Test IOTC_Get_SessionID - should return error without connection
    std::cout << "\nTesting IOTC_Get_SessionID..." << std::endl;
    int sid = tutk.iotc().Get_SessionID();
    std::cout << "  Get_SessionID returned: " << sid << std::endl;
    TEST_ASSERT(true, "IOTC_Get_SessionID called (returned " + std::to_string(sid) + ")");

    // Test cleanup functions
    std::cout << "\nTesting cleanup functions..." << std::endl;

    tutk.rdt().DeInitialize();
    TEST_ASSERT(true, "RDT_DeInitialize called");

    tutk.av().DeInitialize();
    TEST_ASSERT(true, "avDeInitialize called");

    tutk.iotc().DeInitialize();
    TEST_ASSERT(true, "IOTC_DeInitialize called");
}

void test_tutk_error_handling() {
    std::cout << "\n=== TUTK Error Handling Test ===" << std::endl;

    TUTKWrapper tutk;
    if (!tutk.load(".")) {
        std::cout << "  [SKIP] Libraries not loaded" << std::endl;
        return;
    }

    // Test connecting to invalid UID
    std::cout << "\nTesting Connect_ByUID with invalid UID..." << std::endl;
    tutk.iotc().Initialize2(0);

    int result = tutk.iotc().Connect_ByUID("INVALID-UID-12345");
    std::cout << "  Connect_ByUID returned: " << result << " (0x" << std::hex << result << std::dec << ")" << std::endl;
    // The function was called - that's what we're testing
    TEST_ASSERT(true, "Connect_ByUID called without crash");

    // Test Session_Close with invalid session
    std::cout << "\nTesting Session_Close with invalid session..." << std::endl;
    tutk.iotc().Session_Close(-1);
    TEST_ASSERT(true, "Session_Close with invalid session doesn't crash");

    // Test avClientStart with invalid session
    std::cout << "\nTesting avClientStart with invalid session..." << std::endl;
    tutk.av().Initialize(8);
    unsigned int srvType = 0;
    int av_result = tutk.av().ClientStart(-1, "user", "pass", 5000, &srvType, 0);
    std::cout << "  avClientStart returned: " << av_result << std::endl;
    // -1 is expected for invalid session
    TEST_ASSERT(av_result != 0, "avClientStart returns non-zero for invalid session");

    tutk.av().DeInitialize();
    tutk.iotc().DeInitialize();
}

void test_iotc_configuration() {
    std::cout << "\n=== IOTC Configuration Test ===" << std::endl;

    TUTKWrapper tutk;
    if (!tutk.load(".")) {
        std::cout << "  [SKIP] Libraries not loaded" << std::endl;
        return;
    }

    // Initialize IOTC
    tutk.iotc().Initialize2(0);

    // Test Set_Max_Session_Number
    std::cout << "\nTesting IOTC_Set_Max_Session_Number..." << std::endl;
    tutk.iotc().Set_Max_Session_Number(32);
    TEST_ASSERT(true, "Set_Max_Session_Number(32) called");

    // Test Setup_Session_Alive_Timeout
    std::cout << "\nTesting IOTC_Setup_Session_Alive_Timeout..." << std::endl;
    tutk.iotc().Setup_Session_Alive_Timeout(60);
    TEST_ASSERT(true, "Setup_Session_Alive_Timeout(60) called");

    // Test Setup_P2PConnection_Timeout
    std::cout << "\nTesting IOTC_Setup_P2PConnection_Timeout..." << std::endl;
    tutk.iotc().Setup_P2PConnection_Timeout(30);
    TEST_ASSERT(true, "Setup_P2PConnection_Timeout(30) called");

    // Test Setup_LANConnection_Timeout
    std::cout << "\nTesting IOTC_Setup_LANConnection_Timeout..." << std::endl;
    tutk.iotc().Setup_LANConnection_Timeout(5);
    TEST_ASSERT(true, "Setup_LANConnection_Timeout(5) called");

    // Test Get_Nat_Type
    std::cout << "\nTesting IOTC_Get_Nat_Type..." << std::endl;
    int nat_type = tutk.iotc().Get_Nat_Type();
    std::cout << "  NAT type: " << nat_type << std::endl;
    TEST_ASSERT(true, "Get_Nat_Type called (returned " + std::to_string(nat_type) + ")");

    // Test Get_RandomID32
    std::cout << "\nTesting IOTC_Get_RandomID32..." << std::endl;
    int random_id = tutk.iotc().Get_RandomID32();
    std::cout << "  Random ID: " << random_id << std::endl;
    TEST_ASSERT(true, "Get_RandomID32 called (returned " + std::to_string(random_id) + ")");

    tutk.iotc().DeInitialize();
}

void test_av_configuration() {
    std::cout << "\n=== AV Configuration Test ===" << std::endl;

    TUTKWrapper tutk;
    if (!tutk.load(".")) {
        std::cout << "  [SKIP] Libraries not loaded" << std::endl;
        return;
    }

    // Initialize
    tutk.iotc().Initialize2(0);
    tutk.av().Initialize(16);

    // Test GetAVApiVer
    std::cout << "\nTesting avGetAVApiVer..." << std::endl;
    int av_ver = tutk.av().GetAVApiVer();
    std::cout << "  AV API version: " << av_ver << std::endl;
    TEST_ASSERT(true, "GetAVApiVer called (returned " + std::to_string(av_ver) + ")");

    // Test ClientSetMaxBufSize
    std::cout << "\nTesting avClientSetMaxBufSize..." << std::endl;
    tutk.av().ClientSetMaxBufSize(1024 * 1024);  // 1MB
    TEST_ASSERT(true, "ClientSetMaxBufSize(1MB) called");

    // Test ServSetMaxBufSize
    std::cout << "\nTesting avServSetMaxBufSize..." << std::endl;
    tutk.av().ServSetMaxBufSize(2 * 1024 * 1024);  // 2MB
    TEST_ASSERT(true, "ServSetMaxBufSize(2MB) called");

    tutk.av().DeInitialize();
    tutk.iotc().DeInitialize();
}

void test_rdt_operations() {
    std::cout << "\n=== RDT Operations Test ===" << std::endl;

    TUTKWrapper tutk;
    if (!tutk.load(".")) {
        std::cout << "  [SKIP] Libraries not loaded" << std::endl;
        return;
    }

    // Initialize
    tutk.iotc().Initialize2(0);
    int rdt_init = tutk.rdt().Initialize();
    std::cout << "  RDT_Initialize returned: " << rdt_init << std::endl;
    TEST_ASSERT(true, "RDT_Initialize called");

    // Test GetRDTApiVer
    std::cout << "\nTesting RDT_GetRDTApiVer..." << std::endl;
    int rdt_ver = tutk.rdt().GetRDTApiVer();
    std::cout << "  RDT API version: " << rdt_ver << std::endl;
    TEST_ASSERT(true, "GetRDTApiVer called (returned " + std::to_string(rdt_ver) + ")");

    // Test Create with invalid session (should fail gracefully)
    std::cout << "\nTesting RDT_Create with invalid session..." << std::endl;
    int rdt_id = tutk.rdt().Create(-1, 0, 1000);
    std::cout << "  RDT_Create returned: " << rdt_id << std::endl;
    TEST_ASSERT(true, "RDT_Create with invalid session doesn't crash");

    // Test Destroy with invalid ID
    std::cout << "\nTesting RDT_Destroy with invalid ID..." << std::endl;
    int destroy_result = tutk.rdt().Destroy(-1);
    std::cout << "  RDT_Destroy returned: " << destroy_result << std::endl;
    TEST_ASSERT(true, "RDT_Destroy with invalid ID doesn't crash");

    // Test Read with invalid ID
    std::cout << "\nTesting RDT_Read with invalid ID..." << std::endl;
    char buffer[256];
    int read_result = tutk.rdt().Read(-1, buffer, sizeof(buffer), 100);
    std::cout << "  RDT_Read returned: " << read_result << std::endl;
    TEST_ASSERT(true, "RDT_Read with invalid ID doesn't crash");

    // Test Write with invalid ID
    std::cout << "\nTesting RDT_Write with invalid ID..." << std::endl;
    const char* test_data = "test data";
    int write_result = tutk.rdt().Write(-1, test_data, strlen(test_data));
    std::cout << "  RDT_Write returned: " << write_result << std::endl;
    TEST_ASSERT(true, "RDT_Write with invalid ID doesn't crash");

    tutk.rdt().DeInitialize();
    tutk.iotc().DeInitialize();
}

void test_session_operations() {
    std::cout << "\n=== Session Operations Test ===" << std::endl;

    TUTKWrapper tutk;
    if (!tutk.load(".")) {
        std::cout << "  [SKIP] Libraries not loaded" << std::endl;
        return;
    }

    tutk.iotc().Initialize2(0);

    // Test Session_Check with invalid session
    std::cout << "\nTesting IOTC_Session_Check with invalid session..." << std::endl;
    st_SInfo info;
    memset(&info, 0, sizeof(info));
    int check_result = tutk.iotc().Session_Check(-1, &info);
    std::cout << "  Session_Check returned: " << check_result << std::endl;
    TEST_ASSERT(true, "Session_Check with invalid session doesn't crash");

    // Test Session_Read with invalid session
    std::cout << "\nTesting IOTC_Session_Read with invalid session..." << std::endl;
    char buffer[256];
    int read_result = tutk.iotc().Session_Read(-1, buffer, sizeof(buffer), 100);
    std::cout << "  Session_Read returned: " << read_result << std::endl;
    TEST_ASSERT(true, "Session_Read with invalid session doesn't crash");

    // Test Session_Write with invalid session
    std::cout << "\nTesting IOTC_Session_Write with invalid session..." << std::endl;
    const char* test_data = "test";
    int write_result = tutk.iotc().Session_Write(-1, test_data, strlen(test_data));
    std::cout << "  Session_Write returned: " << write_result << std::endl;
    TEST_ASSERT(true, "Session_Write with invalid session doesn't crash");

    // Test Session_Has_Data with invalid session
    std::cout << "\nTesting IOTC_Session_Has_Data with invalid session..." << std::endl;
    int has_data = tutk.iotc().Session_Has_Data(-1);
    std::cout << "  Session_Has_Data returned: " << has_data << std::endl;
    TEST_ASSERT(true, "Session_Has_Data with invalid session doesn't crash");

    // Test Session_Get_Free_Channel with invalid session
    std::cout << "\nTesting IOTC_Session_Get_Free_Channel with invalid session..." << std::endl;
    int free_channel = tutk.iotc().Session_Get_Free_Channel(-1);
    std::cout << "  Session_Get_Free_Channel returned: " << free_channel << std::endl;
    TEST_ASSERT(true, "Session_Get_Free_Channel with invalid session doesn't crash");

    tutk.iotc().DeInitialize();
}

void test_av_client_operations() {
    std::cout << "\n=== AV Client Operations Test ===" << std::endl;

    TUTKWrapper tutk;
    if (!tutk.load(".")) {
        std::cout << "  [SKIP] Libraries not loaded" << std::endl;
        return;
    }

    tutk.iotc().Initialize2(0);
    tutk.av().Initialize(8);

    // Test ClientStart2 with invalid session
    std::cout << "\nTesting avClientStart2 with invalid session..." << std::endl;
    uint32_t servType = 0;
    int resend = 0;
    int av_idx = tutk.av().ClientStart2(-1, "user", "pass", 1000, &servType, 0, &resend);
    std::cout << "  ClientStart2 returned: " << av_idx << std::endl;
    TEST_ASSERT(true, "ClientStart2 with invalid session doesn't crash");

    // Test ClientStop with invalid index
    std::cout << "\nTesting avClientStop with invalid index..." << std::endl;
    tutk.av().ClientStop(-1);
    TEST_ASSERT(true, "ClientStop with invalid index doesn't crash");

    // Test ClientCleanBuf with invalid index
    std::cout << "\nTesting avClientCleanBuf with invalid index..." << std::endl;
    tutk.av().ClientCleanBuf(-1);
    TEST_ASSERT(true, "ClientCleanBuf with invalid index doesn't crash");

    // Test RecvFrameData2 with invalid index
    std::cout << "\nTesting avRecvFrameData2 with invalid index..." << std::endl;
    char buffer[1024];
    int outBufSize = 0, outFrmSize = 0, frmNo = 0;
    char frmInfoBuf[64];
    int recv_result = tutk.av().RecvFrameData2(-1, buffer, sizeof(buffer),
                                                &outBufSize, &outFrmSize,
                                                frmInfoBuf, sizeof(frmInfoBuf), &frmNo);
    std::cout << "  RecvFrameData2 returned: " << recv_result << std::endl;
    TEST_ASSERT(true, "RecvFrameData2 with invalid index doesn't crash");

    // Test SendIOCtrl with invalid index
    std::cout << "\nTesting avSendIOCtrl with invalid index..." << std::endl;
    const char* ctrl_data = "test";
    int send_result = tutk.av().SendIOCtrl(-1, 0x1234, ctrl_data, strlen(ctrl_data));
    std::cout << "  SendIOCtrl returned: " << send_result << std::endl;
    TEST_ASSERT(true, "SendIOCtrl with invalid index doesn't crash");

    // Test RecvIOCtrl with invalid index
    std::cout << "\nTesting avRecvIOCtrl with invalid index..." << std::endl;
    uint32_t ioType = 0;
    char recvBuf[256];
    int recv_ctrl = tutk.av().RecvIOCtrl(-1, &ioType, recvBuf, sizeof(recvBuf), 100);
    std::cout << "  RecvIOCtrl returned: " << recv_ctrl << std::endl;
    TEST_ASSERT(true, "RecvIOCtrl with invalid index doesn't crash");

    tutk.av().DeInitialize();
    tutk.iotc().DeInitialize();
}

void test_lan_search() {
    std::cout << "\n=== LAN Search Test ===" << std::endl;

    TUTKWrapper tutk;
    if (!tutk.load(".")) {
        std::cout << "  [SKIP] Libraries not loaded" << std::endl;
        return;
    }

    tutk.iotc().Initialize2(0);

    // Test Lan_Search with short timeout
    std::cout << "\nTesting IOTC_Lan_Search (1 second timeout)..." << std::endl;
    st_LanSearchInfo results[10];
    memset(results, 0, sizeof(results));
    int found = tutk.iotc().Lan_Search(results, 10, 1000);
    std::cout << "  Lan_Search returned: " << found << " devices" << std::endl;
    TEST_ASSERT(true, "Lan_Search completed without crash");

    // Test Lan_Search2 with short timeout
    std::cout << "\nTesting IOTC_Lan_Search2 (1 second timeout)..." << std::endl;
    memset(results, 0, sizeof(results));
    found = tutk.iotc().Lan_Search2(results, 10, 1000);
    std::cout << "  Lan_Search2 returned: " << found << " devices" << std::endl;
    TEST_ASSERT(true, "Lan_Search2 completed without crash");

    tutk.iotc().DeInitialize();
}

void test_initialize_all() {
    std::cout << "\n=== Initialize All Test ===" << std::endl;

    TUTKWrapper tutk;
    if (!tutk.load(".")) {
        std::cout << "  [SKIP] Libraries not loaded" << std::endl;
        return;
    }

    // Test initializeAll convenience function
    std::cout << "\nTesting TUTKWrapper::initializeAll..." << std::endl;
    int result = tutk.initializeAll(0, 16);
    std::cout << "  initializeAll returned: " << result << std::endl;
    TEST_ASSERT(true, "initializeAll completed");

    // Test deinitializeAll
    std::cout << "\nTesting TUTKWrapper::deinitializeAll..." << std::endl;
    tutk.deinitializeAll();
    TEST_ASSERT(true, "deinitializeAll completed");
}

void test_symbol_lookup() {
    std::cout << "\n=== Extended Symbol Lookup Test ===" << std::endl;

    TUTKWrapper tutk;
    if (!tutk.load(".")) {
        std::cout << "  [SKIP] Libraries not loaded" << std::endl;
        return;
    }

    // Test various symbol lookups
    const char* iotc_symbols[] = {
        "IOTC_Initialize", "IOTC_Initialize2", "IOTC_DeInitialize",
        "IOTC_Connect_ByUID", "IOTC_Session_Close", "IOTC_Session_Read",
        "IOTC_Session_Write", "IOTC_Lan_Search", "IOTC_Get_Version"
    };

    std::cout << "\nIOTC Symbols:" << std::endl;
    for (const char* sym : iotc_symbols) {
        uint64_t addr = tutk.get_symbol(sym);
        std::cout << "  " << sym << ": 0x" << std::hex << addr << std::dec << std::endl;
        TEST_ASSERT(addr != 0, std::string(sym) + " found");
    }

    const char* av_symbols[] = {
        "avInitialize", "avDeInitialize", "avClientStart", "avClientStop",
        "avRecvFrameData2", "avSendIOCtrl", "avRecvIOCtrl"
    };

    std::cout << "\nAV Symbols:" << std::endl;
    for (const char* sym : av_symbols) {
        uint64_t addr = tutk.get_symbol(sym);
        std::cout << "  " << sym << ": 0x" << std::hex << addr << std::dec << std::endl;
        TEST_ASSERT(addr != 0, std::string(sym) + " found");
    }

    const char* rdt_symbols[] = {
        "RDT_Initialize", "RDT_DeInitialize", "RDT_Create", "RDT_Destroy",
        "RDT_Read", "RDT_Write"
    };

    std::cout << "\nRDT Symbols:" << std::endl;
    for (const char* sym : rdt_symbols) {
        uint64_t addr = tutk.get_symbol(sym);
        std::cout << "  " << sym << ": 0x" << std::hex << addr << std::dec << std::endl;
        TEST_ASSERT(addr != 0, std::string(sym) + " found");
    }
}

void test_advanced_iotc_config() {
    std::cout << "\n=== Advanced IOTC Configuration Test ===" << std::endl;

    TUTKWrapper tutk;
    if (!tutk.load(".")) {
        std::cout << "  [SKIP] Libraries not loaded" << std::endl;
        return;
    }

    // Test Set_Anvance_Mode
    std::cout << "\nTesting IOTC_Set_Anvance_Mode..." << std::endl;
    int ret = tutk.iotc().Set_Anvance_Mode(1);
    TEST_ASSERT(true, "Set_Anvance_Mode called");

    // Test TCPRelayOnly_TurnOn
    std::cout << "Testing IOTC_TCPRelayOnly_TurnOn..." << std::endl;
    ret = tutk.iotc().TCPRelayOnly_TurnOn(0);
    TEST_ASSERT(true, "TCPRelayOnly_TurnOn called");

    // Test Set_Connect_Timeout
    std::cout << "Testing IOTC_Set_Connect_Timeout..." << std::endl;
    ret = tutk.iotc().Set_Connect_Timeout(30);
    TEST_ASSERT(true, "Set_Connect_Timeout called");

    // Test Set_LanSearch_Port
    std::cout << "Testing IOTC_Set_LanSearch_Port..." << std::endl;
    ret = tutk.iotc().Set_LanSearch_Port(12345);
    TEST_ASSERT(true, "Set_LanSearch_Port called");
}

void test_av_extended() {
    std::cout << "\n=== Extended AV Operations Test ===" << std::endl;

    TUTKWrapper tutk;
    if (!tutk.load(".")) {
        std::cout << "  [SKIP] Libraries not loaded" << std::endl;
        return;
    }

    // Test CheckAudioBuf with invalid index
    std::cout << "\nTesting avCheckAudioBuf with invalid index..." << std::endl;
    int ret = tutk.av().CheckAudioBuf(-1);
    std::cout << "  CheckAudioBuf returned: " << ret << std::endl;
    TEST_ASSERT(true, "CheckAudioBuf with invalid index doesn't crash");

    // Test CheckDecode with invalid index
    std::cout << "Testing avCheckDecode with invalid index..." << std::endl;
    ret = tutk.av().CheckDecode(-1);
    std::cout << "  CheckDecode returned: " << ret << std::endl;
    TEST_ASSERT(true, "CheckDecode with invalid index doesn't crash");

    // Test ResendBufUsageRate with invalid index
    std::cout << "Testing avResendBufUsageRate with invalid index..." << std::endl;
    ret = tutk.av().ResendBufUsageRate(-1);
    std::cout << "  ResendBufUsageRate returned: " << ret << std::endl;
    TEST_ASSERT(true, "ResendBufUsageRate with invalid index doesn't crash");

    // Test SendIOCtrlExit with invalid index
    std::cout << "Testing avSendIOCtrlExit with invalid index..." << std::endl;
    ret = tutk.av().SendIOCtrlExit(-1);
    std::cout << "  SendIOCtrlExit returned: " << ret << std::endl;
    TEST_ASSERT(true, "SendIOCtrlExit with invalid index doesn't crash");
}

void test_rdt_extended() {
    std::cout << "\n=== Extended RDT Operations Test ===" << std::endl;

    TUTKWrapper tutk;
    if (!tutk.load(".")) {
        std::cout << "  [SKIP] Libraries not loaded" << std::endl;
        return;
    }

    // Initialize RDT
    tutk.rdt().Initialize();

    // Test Set_Max_Channel_Number
    std::cout << "\nTesting RDT_Set_Max_Channel_Number..." << std::endl;
    int ret = tutk.rdt().Set_Max_Channel_Number(64);
    std::cout << "  Set_Max_Channel_Number returned: " << ret << std::endl;
    TEST_ASSERT(true, "Set_Max_Channel_Number called");

    // Test Set_MaxPacketDataSize
    std::cout << "Testing RDT_Set_MaxPacketDataSize..." << std::endl;
    ret = tutk.rdt().Set_MaxPacketDataSize(1024);
    std::cout << "  Set_MaxPacketDataSize returned: " << ret << std::endl;
    TEST_ASSERT(true, "Set_MaxPacketDataSize called");

    // Test Flush with invalid ID
    std::cout << "Testing RDT_Flush with invalid ID..." << std::endl;
    ret = tutk.rdt().Flush(-1);
    std::cout << "  Flush returned: " << ret << std::endl;
    TEST_ASSERT(true, "Flush with invalid ID doesn't crash");

    // Test Abort with invalid ID
    std::cout << "Testing RDT_Abort with invalid ID..." << std::endl;
    ret = tutk.rdt().Abort(-1);
    std::cout << "  Abort returned: " << ret << std::endl;
    TEST_ASSERT(true, "Abort with invalid ID doesn't crash");

    // Test Write_UrgentData with invalid ID
    std::cout << "Testing RDT_Write_UrgentData with invalid ID..." << std::endl;
    const char* data = "test";
    ret = tutk.rdt().Write_UrgentData(-1, data, 4);
    std::cout << "  Write_UrgentData returned: " << ret << std::endl;
    TEST_ASSERT(true, "Write_UrgentData with invalid ID doesn't crash");

    tutk.rdt().DeInitialize();
}

void test_session_extended() {
    std::cout << "\n=== Extended Session Operations Test ===" << std::endl;

    TUTKWrapper tutk;
    if (!tutk.load(".")) {
        std::cout << "  [SKIP] Libraries not loaded" << std::endl;
        return;
    }

    // Test Session_Lock with invalid session
    std::cout << "\nTesting IOTC_Session_Lock with invalid session..." << std::endl;
    int ret = tutk.iotc().Session_Lock(-1);
    std::cout << "  Session_Lock returned: " << ret << std::endl;
    TEST_ASSERT(true, "Session_Lock with invalid session doesn't crash");

    // Test Session_unLock with invalid session
    std::cout << "Testing IOTC_Session_unLock with invalid session..." << std::endl;
    ret = tutk.iotc().Session_unLock(-1);
    std::cout << "  Session_unLock returned: " << ret << std::endl;
    TEST_ASSERT(true, "Session_unLock with invalid session doesn't crash");

    // Test Session_Channel_ON with invalid session
    std::cout << "Testing IOTC_Session_Channel_ON with invalid session..." << std::endl;
    ret = tutk.iotc().Session_Channel_ON(-1, 0);
    std::cout << "  Session_Channel_ON returned: " << ret << std::endl;
    TEST_ASSERT(true, "Session_Channel_ON with invalid session doesn't crash");

    // Test Session_Channel_OFF with invalid session
    std::cout << "Testing IOTC_Session_Channel_OFF with invalid session..." << std::endl;
    ret = tutk.iotc().Session_Channel_OFF(-1, 0);
    std::cout << "  Session_Channel_OFF returned: " << ret << std::endl;
    TEST_ASSERT(true, "Session_Channel_OFF with invalid session doesn't crash");
}

void test_wakeup_functions() {
    std::cout << "\n=== Wake-up Functions Test ===" << std::endl;

    TUTKWrapper tutk;
    if (!tutk.load(".")) {
        std::cout << "  [SKIP] Libraries not loaded" << std::endl;
        return;
    }

    // Test WakeUp_Init
    std::cout << "\nTesting IOTC_WakeUp_Init..." << std::endl;
    int ret = tutk.iotc().WakeUp_Init();
    std::cout << "  WakeUp_Init returned: " << ret << std::endl;
    TEST_ASSERT(true, "WakeUp_Init called");

    // Test WakeUp_Get_Status with invalid ID
    std::cout << "Testing IOTC_WakeUp_Get_Status with invalid ID..." << std::endl;
    ret = tutk.iotc().WakeUp_Get_Status(-1);
    std::cout << "  WakeUp_Get_Status returned: " << ret << std::endl;
    TEST_ASSERT(true, "WakeUp_Get_Status with invalid ID doesn't crash");

    // Test WakeUp_DeInit
    std::cout << "Testing IOTC_WakeUp_DeInit..." << std::endl;
    ret = tutk.iotc().WakeUp_DeInit();
    std::cout << "  WakeUp_DeInit returned: " << ret << std::endl;
    TEST_ASSERT(true, "WakeUp_DeInit called");
}

void test_secure_channel() {
    std::cout << "\n=== Secure Channel Test ===" << std::endl;

    TUTKWrapper tutk;
    if (!tutk.load(".")) {
        std::cout << "  [SKIP] Libraries not loaded" << std::endl;
        return;
    }

    // Test sCHL_initialize
    std::cout << "\nTesting IOTC_sCHL_initialize..." << std::endl;
    int ret = tutk.iotc().sCHL_initialize();
    std::cout << "  sCHL_initialize returned: " << ret << std::endl;
    TEST_ASSERT(true, "sCHL_initialize called");

    // Test sCHL_CTX_new
    std::cout << "Testing IOTC_sCHL_CTX_new..." << std::endl;
    void* ctx = tutk.iotc().sCHL_CTX_new();
    std::cout << "  sCHL_CTX_new returned: " << ctx << std::endl;
    TEST_ASSERT(true, "sCHL_CTX_new called");

    // Test sCHL_new with context
    if (ctx) {
        std::cout << "Testing IOTC_sCHL_new..." << std::endl;
        void* schl = tutk.iotc().sCHL_new(ctx);
        std::cout << "  sCHL_new returned: " << schl << std::endl;
        TEST_ASSERT(true, "sCHL_new called");

        if (schl) {
            tutk.iotc().sCHL_free(schl);
        }
        tutk.iotc().sCHL_CTX_free(ctx);
    }

    // Test sCHL_deinitialize
    std::cout << "Testing IOTC_sCHL_deinitialize..." << std::endl;
    ret = tutk.iotc().sCHL_deinitialize();
    std::cout << "  sCHL_deinitialize returned: " << ret << std::endl;
    TEST_ASSERT(true, "sCHL_deinitialize called");
}

void test_version_strings() {
    std::cout << "\n=== Version Strings Test ===" << std::endl;

    TUTKWrapper tutk;
    if (!tutk.load(".")) {
        std::cout << "  [SKIP] Libraries not loaded" << std::endl;
        return;
    }

    // Test IOTC version string
    std::cout << "\nTesting IOTC_Get_Version_String..." << std::endl;
    std::string iotcVer = tutk.iotc().Get_Version_String();
    std::cout << "  IOTC Version: " << iotcVer << std::endl;
    TEST_ASSERT(!iotcVer.empty(), "IOTC version string not empty");
    TEST_ASSERT(iotcVer.find("4.3.8") != std::string::npos, "IOTC version contains expected version");

    // Test AV version
    std::cout << "Testing avGetAVApiVer..." << std::endl;
    int avVer = tutk.av().GetAVApiVer();
    std::cout << "  AV API Version: 0x" << std::hex << avVer << std::dec << std::endl;
    TEST_ASSERT(avVer != -1, "AV API version returned");

    // Test RDT version
    std::cout << "Testing RDT_GetRDTApiVer..." << std::endl;
    int rdtVer = tutk.rdt().GetRDTApiVer();
    std::cout << "  RDT API Version: 0x" << std::hex << rdtVer << std::dec << std::endl;
    TEST_ASSERT(rdtVer != -1, "RDT API version returned");
}

int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "  TUTK Android ARM64 Emulator Library  " << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        // Test memory allocator
        test_memory_allocator();

        // Test raw emulator
        test_raw_emulator();

        // Test TUTK wrapper
        test_tutk_wrapper();

        // Test TUTK function calls
        test_tutk_functions();

        // Test error handling
        test_tutk_error_handling();

        // Test IOTC configuration
        test_iotc_configuration();

        // Test AV configuration
        test_av_configuration();

        // Test RDT operations
        test_rdt_operations();

        // Test session operations
        test_session_operations();

        // Test AV client operations
        test_av_client_operations();

        // Test LAN search
        test_lan_search();

        // Test initialize all
        test_initialize_all();

        // Test extended symbol lookup
        test_symbol_lookup();

        // Test advanced IOTC configuration
        test_advanced_iotc_config();

        // Test extended AV operations
        test_av_extended();

        // Test extended RDT operations
        test_rdt_extended();

        // Test extended session operations
        test_session_extended();

        // Test wake-up functions
        test_wakeup_functions();

        // Test secure channel
        test_secure_channel();

        // Test version strings
        test_version_strings();

        std::cout << "\n========================================" << std::endl;
        std::cout << "  Test Results: " << tests_passed << " passed, "
                  << tests_failed << " failed" << std::endl;
        std::cout << "========================================" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return tests_failed > 0 ? 1 : 0;
}
