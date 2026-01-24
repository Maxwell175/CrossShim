/**
 * HLE User/Group Functions
 * getpwuid, getpwuid_r, getpwnam, getpwnam_r
 * getgrnam, getgrgid, getgroups
 * getauxval, if_nametoindex
 */

#include "debug_log.h"
#include "cross_shim.h"
#include "hle_manager.h"
#include "memory_manager.h"
#include "emu_compat.h"
#include <cstring>
#include <grp.h>
#include <iostream>
#include <net/if.h>
#include <pwd.h>
#include <random>
#include <fstream>

namespace cross_shim {

// get_reg and set_reg are provided by emu_compat.h

static std::string read_string(Emulator &emu, uint64_t addr,
                               size_t max_len = 4096) {
  std::string result;
  char c;
  for (size_t i = 0; i < max_len; i++) {
    if (!emu.mem_read(addr + i, &c, 1) || c == '\0')
      break;
    result += c;
  }
  return result;
}

// Static storage for passwd/group structures (returned by non-reentrant
// functions)
static uint64_t g_passwd_struct_addr = 0;
static uint64_t g_group_struct_addr = 0;

// Helper to write a passwd structure to emulated memory
// ARM64 Android struct passwd layout:
// char *pw_name (8 bytes)
// char *pw_passwd (8 bytes)
// uid_t pw_uid (4 bytes)
// gid_t pw_gid (4 bytes)
// char *pw_gecos (8 bytes)
// char *pw_dir (8 bytes)
// char *pw_shell (8 bytes)
// Total: 48 bytes
static uint64_t write_passwd_struct(Emulator &emu, uid_t uid,
                                    const char *name) {
  // Allocate space for struct and strings
  size_t name_len = strlen(name) + 1;
  const char *passwd = "x";
  const char *gecos = "Emulated User";
  const char *dir = "/data/local";
  const char *shell = "/system/bin/sh";

  size_t total_str_size =
      name_len + 2 + strlen(gecos) + 1 + strlen(dir) + 1 + strlen(shell) + 1;
  uint64_t str_base = emu.memory().heap().allocate(total_str_size, 8);
  uint64_t struct_addr = emu.memory().heap().allocate(48, 8);

  // Write strings
  uint64_t name_addr = str_base;
  emu.mem_write(name_addr, name, name_len);

  uint64_t passwd_addr = name_addr + name_len;
  emu.mem_write(passwd_addr, passwd, 2);

  uint64_t gecos_addr = passwd_addr + 2;
  emu.mem_write(gecos_addr, gecos, strlen(gecos) + 1);

  uint64_t dir_addr = gecos_addr + strlen(gecos) + 1;
  emu.mem_write(dir_addr, dir, strlen(dir) + 1);

  uint64_t shell_addr = dir_addr + strlen(dir) + 1;
  emu.mem_write(shell_addr, shell, strlen(shell) + 1);

  // Write struct passwd
  uint8_t pw_buf[48] = {0};
  memcpy(pw_buf + 0, &name_addr, 8);   // pw_name
  memcpy(pw_buf + 8, &passwd_addr, 8); // pw_passwd
  uint32_t uid32 = uid;
  memcpy(pw_buf + 16, &uid32, 4);      // pw_uid
  memcpy(pw_buf + 20, &uid32, 4);      // pw_gid (same as uid)
  memcpy(pw_buf + 24, &gecos_addr, 8); // pw_gecos
  memcpy(pw_buf + 32, &dir_addr, 8);   // pw_dir
  memcpy(pw_buf + 40, &shell_addr, 8); // pw_shell

  emu.mem_write(struct_addr, pw_buf, 48);
  return struct_addr;
}

// Helper to write a group structure to emulated memory
// ARM64 Android struct group layout:
// char *gr_name (8 bytes)
// char *gr_passwd (8 bytes)
// gid_t gr_gid (4 bytes + 4 padding)
// char **gr_mem (8 bytes)
// Total: 32 bytes
static uint64_t write_group_struct(Emulator &emu, gid_t gid, const char *name) {
  size_t name_len = strlen(name) + 1;
  const char *passwd = "x";

  uint64_t str_base = emu.memory().heap().allocate(name_len + 2 + 8, 8);
  uint64_t struct_addr = emu.memory().heap().allocate(32, 8);

  // Write strings
  uint64_t name_addr = str_base;
  emu.mem_write(name_addr, name, name_len);

  uint64_t passwd_addr = name_addr + name_len;
  emu.mem_write(passwd_addr, passwd, 2);

  // Write empty member list (NULL pointer)
  uint64_t mem_addr = passwd_addr + 2;
  uint64_t null_ptr = 0;
  emu.mem_write(mem_addr, &null_ptr, 8);

  // Write struct group
  uint8_t gr_buf[32] = {0};
  memcpy(gr_buf + 0, &name_addr, 8);   // gr_name
  memcpy(gr_buf + 8, &passwd_addr, 8); // gr_passwd
  uint32_t gid32 = gid;
  memcpy(gr_buf + 16, &gid32, 4);    // gr_gid
  memcpy(gr_buf + 24, &mem_addr, 8); // gr_mem

  emu.mem_write(struct_addr, gr_buf, 32);
  return struct_addr;
}

void register_hle_user(HleManager &hle) {
  // ========================================================================
  // Password database
  // ========================================================================

  hle.register_function("getpwuid", [](Emulator &emu) {
    uid_t uid = get_reg(emu, UC_ARM64_REG_X0);

    // Return a fake but valid passwd structure
    const char *name = (uid == 0) ? "root" : "user";
    g_passwd_struct_addr = write_passwd_struct(emu, uid, name);
    set_reg(emu, UC_ARM64_REG_X0, g_passwd_struct_addr);
  });

  hle.register_function("getpwuid_r", [](Emulator &emu) {
    uid_t uid = get_reg(emu, UC_ARM64_REG_X0);
    uint64_t pwd = get_reg(emu, UC_ARM64_REG_X1);
    uint64_t buf = get_reg(emu, UC_ARM64_REG_X2);
    size_t buflen = get_reg(emu, UC_ARM64_REG_X3);
    uint64_t result = get_reg(emu, UC_ARM64_REG_X4);

    if (buflen < 128) {
      // Buffer too small
      set_reg(emu, UC_ARM64_REG_X0, 34); // ERANGE
      return;
    }

    const char *name = (uid == 0) ? "root" : "user";
    const char *passwd = "x";
    const char *gecos = "Emulated User";
    const char *dir = "/data/local";
    const char *shell = "/system/bin/sh";

    // Write strings to buffer
    uint64_t name_addr = buf;
    emu.mem_write(name_addr, name, strlen(name) + 1);

    uint64_t passwd_addr = name_addr + strlen(name) + 1;
    emu.mem_write(passwd_addr, passwd, 2);

    uint64_t gecos_addr = passwd_addr + 2;
    emu.mem_write(gecos_addr, gecos, strlen(gecos) + 1);

    uint64_t dir_addr = gecos_addr + strlen(gecos) + 1;
    emu.mem_write(dir_addr, dir, strlen(dir) + 1);

    uint64_t shell_addr = dir_addr + strlen(dir) + 1;
    emu.mem_write(shell_addr, shell, strlen(shell) + 1);

    // Write struct passwd
    uint8_t pw_buf[48] = {0};
    memcpy(pw_buf + 0, &name_addr, 8);
    memcpy(pw_buf + 8, &passwd_addr, 8);
    uint32_t uid32 = uid;
    memcpy(pw_buf + 16, &uid32, 4);
    memcpy(pw_buf + 20, &uid32, 4);
    memcpy(pw_buf + 24, &gecos_addr, 8);
    memcpy(pw_buf + 32, &dir_addr, 8);
    memcpy(pw_buf + 40, &shell_addr, 8);
    emu.mem_write(pwd, pw_buf, 48);

    // Set result pointer
    if (result) {
      emu.mem_write(result, &pwd, sizeof(pwd));
    }
    set_reg(emu, UC_ARM64_REG_X0, 0);
  });

  hle.register_function("getpwnam", [](Emulator &emu) {
    uint64_t name_addr = get_reg(emu, UC_ARM64_REG_X0);
    std::string name = read_string(emu, name_addr);

    uid_t uid = (name == "root") ? 0 : 1000;
    g_passwd_struct_addr = write_passwd_struct(emu, uid, name.c_str());
    set_reg(emu, UC_ARM64_REG_X0, g_passwd_struct_addr);
  });

  hle.register_function("getpwnam_r", [](Emulator &emu) {
    uint64_t name_ptr = get_reg(emu, UC_ARM64_REG_X0);
    uint64_t pwd = get_reg(emu, UC_ARM64_REG_X1);
    uint64_t buf = get_reg(emu, UC_ARM64_REG_X2);
    size_t buflen = get_reg(emu, UC_ARM64_REG_X3);
    uint64_t result = get_reg(emu, UC_ARM64_REG_X4);

    std::string name = read_string(emu, name_ptr);

    if (buflen < 128) {
      set_reg(emu, UC_ARM64_REG_X0, 34); // ERANGE
      return;
    }

    uid_t uid = (name == "root") ? 0 : 1000;
    const char *passwd = "x";
    const char *gecos = "Emulated User";
    const char *dir = "/data/local";
    const char *shell = "/system/bin/sh";

    uint64_t name_addr = buf;
    emu.mem_write(name_addr, name.c_str(), name.length() + 1);

    uint64_t passwd_addr = name_addr + name.length() + 1;
    emu.mem_write(passwd_addr, passwd, 2);

    uint64_t gecos_addr = passwd_addr + 2;
    emu.mem_write(gecos_addr, gecos, strlen(gecos) + 1);

    uint64_t dir_addr = gecos_addr + strlen(gecos) + 1;
    emu.mem_write(dir_addr, dir, strlen(dir) + 1);

    uint64_t shell_addr = dir_addr + strlen(dir) + 1;
    emu.mem_write(shell_addr, shell, strlen(shell) + 1);

    uint8_t pw_buf[48] = {0};
    memcpy(pw_buf + 0, &name_addr, 8);
    memcpy(pw_buf + 8, &passwd_addr, 8);
    uint32_t uid32 = uid;
    memcpy(pw_buf + 16, &uid32, 4);
    memcpy(pw_buf + 20, &uid32, 4);
    memcpy(pw_buf + 24, &gecos_addr, 8);
    memcpy(pw_buf + 32, &dir_addr, 8);
    memcpy(pw_buf + 40, &shell_addr, 8);
    emu.mem_write(pwd, pw_buf, 48);

    if (result) {
      emu.mem_write(result, &pwd, sizeof(pwd));
    }
    set_reg(emu, UC_ARM64_REG_X0, 0);
  });

  // ========================================================================
  // Group database
  // ========================================================================

  hle.register_function("getgrnam", [](Emulator &emu) {
    uint64_t name_addr = get_reg(emu, UC_ARM64_REG_X0);
    std::string name = read_string(emu, name_addr);

    gid_t gid = (name == "root") ? 0 : 1000;
    g_group_struct_addr = write_group_struct(emu, gid, name.c_str());
    set_reg(emu, UC_ARM64_REG_X0, g_group_struct_addr);
  });

  hle.register_function("getgrgid", [](Emulator &emu) {
    gid_t gid = get_reg(emu, UC_ARM64_REG_X0);

    const char *name = (gid == 0) ? "root" : "users";
    g_group_struct_addr = write_group_struct(emu, gid, name);
    set_reg(emu, UC_ARM64_REG_X0, g_group_struct_addr);
  });

  hle.register_function("getgroups", [](Emulator &emu) {
    int size = get_reg(emu, UC_ARM64_REG_X0);
    uint64_t list = get_reg(emu, UC_ARM64_REG_X1);

    // Return 1 group (the primary group)
    if (size == 0) {
      set_reg(emu, UC_ARM64_REG_X0, 1); // Return count
      return;
    }

    if (size >= 1 && list) {
      gid_t gid = 1000; // Default user group
      emu.mem_write(list, &gid, sizeof(gid));
    }
    set_reg(emu, UC_ARM64_REG_X0, 1);
  });

  // ========================================================================
  // Auxiliary vector
  // ========================================================================

  hle.register_function("getauxval", [](Emulator &emu) {
    unsigned long type = get_reg(emu, UC_ARM64_REG_X0);

    // Return reasonable defaults for common aux values
    uint64_t result = 0;
    switch (type) {
    case 6: // AT_PAGESZ
      result = 4096;
      break;
    case 16: // AT_HWCAP
      // Set HWCAP_ATOMICS (bit 8) to indicate LSE atomics support
      // This allows the runtime to use LDADD/LDCLR/etc. instead of LDXR/STXR
      // loops
      result = (1 << 8); // HWCAP_ATOMICS
      EMU_LOG << "[HLE] getauxval(AT_HWCAP) returning 0x" << std::hex
                << result << std::dec << " (HWCAP_ATOMICS)" << std::endl;
      break;
    case 23:      // AT_SECURE
      result = 0; // Not running setuid
      break;
    case 25: { // AT_RANDOM
      // AT_RANDOM should point to 16 random bytes provided by kernel
      // OpenSSL uses this for entropy seeding - CRITICAL for DTLS/TLS to work
      static uint64_t at_random_addr = 0;
      if (at_random_addr == 0) {
        at_random_addr = emu.memory().heap().allocate(16, 8);
        uint8_t random_bytes[16];

        // Try to get cryptographically secure random bytes from /dev/urandom
        std::ifstream urandom("/dev/urandom", std::ios::binary);
        if (urandom) {
          urandom.read(reinterpret_cast<char*>(random_bytes), 16);
          urandom.close();
        } else {
          // Fallback to std::random_device
          std::random_device rd;
          for (int i = 0; i < 4; i++) {
            uint32_t val = rd();
            memcpy(random_bytes + i * 4, &val, 4);
          }
        }

        emu.mem_write(at_random_addr, random_bytes, 16);
        EMU_LOG << "[HLE] getauxval(AT_RANDOM) allocated 16 random bytes at 0x"
                  << std::hex << at_random_addr << std::dec << std::endl;
      }
      result = at_random_addr;
      break;
    }
    case 26: // AT_HWCAP2
      result = 0;
      break;
    default:
      result = 0;
      break;
    }
    set_reg(emu, UC_ARM64_REG_X0, result);
  });

  // ========================================================================
  // Network interface
  // ========================================================================

  hle.register_function("if_nametoindex", [](Emulator &emu) {
    uint64_t ifname_addr = get_reg(emu, UC_ARM64_REG_X0);
    std::string ifname = read_string(emu, ifname_addr);

    unsigned int idx = if_nametoindex(ifname.c_str());
    set_reg(emu, UC_ARM64_REG_X0, idx);
  });

  hle.register_function("if_indextoname", [](Emulator &emu) {
    unsigned int ifindex = get_reg(emu, UC_ARM64_REG_X0);
    uint64_t ifname_addr = get_reg(emu, UC_ARM64_REG_X1);

    char ifname[IF_NAMESIZE];
    if (if_indextoname(ifindex, ifname)) {
      emu.mem_write(ifname_addr, ifname, strlen(ifname) + 1);
      set_reg(emu, UC_ARM64_REG_X0, ifname_addr);
    } else {
      set_reg(emu, UC_ARM64_REG_X0, 0);
    }
  });

  // ========================================================================
  // Host/service resolution
  // ========================================================================

  hle.register_function("gethostbyname", [](Emulator &emu) {
    // Return NULL (not supported)
    set_reg(emu, UC_ARM64_REG_X0, 0);
  });

  hle.register_function(
      "gethostbyaddr", [](Emulator &emu) { set_reg(emu, UC_ARM64_REG_X0, 0); });

  hle.register_function(
      "getservbyname", [](Emulator &emu) { set_reg(emu, UC_ARM64_REG_X0, 0); });

  hle.register_function(
      "getservbyport", [](Emulator &emu) { set_reg(emu, UC_ARM64_REG_X0, 0); });

  hle.register_function("getnameinfo", [](Emulator &emu) {
    // Return error (not supported)
    set_reg(emu, UC_ARM64_REG_X0, -1);
  });

  hle.register_function(
      "res_init", [](Emulator &emu) { set_reg(emu, UC_ARM64_REG_X0, 0); });

  hle.register_function("__get_h_errno", [](Emulator &emu) {
    // Return pointer to h_errno (allocate if needed)
    static uint64_t h_errno_addr = 0;
    if (h_errno_addr == 0) {
      h_errno_addr = emu.memory().heap().allocate(4, 4);
      int zero = 0;
      emu.mem_write(h_errno_addr, &zero, sizeof(zero));
    }
    set_reg(emu, UC_ARM64_REG_X0, h_errno_addr);
  });
}

} // namespace cross_shim
