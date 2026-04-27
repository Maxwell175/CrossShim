/**
 * HLE Search Functions
 * Linear search: lfind, lsearch
 * Binary tree: tfind, tsearch, tdelete, twalk, tdestroy
 * Hash table: hcreate, hsearch, hdestroy, hcreate_r, hsearch_r, hdestroy_r
 * Queue: insque, remque
 */

#include "debug_log.h"
#include "hle_manager.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "emu_compat.h"
#include <search.h>
#include <vector>
#include <unordered_map>
#include <memory>
#include <cstring>
#include <cerrno>

namespace cross_shim {

static std::string read_string(Emulator& emu, uint64_t addr, size_t max_len = 4096) {
    std::string result;
    char c;
    for (size_t i = 0; i < max_len; i++) {
        if (!emu.mem_read(addr + i, &c, 1) || c == '\0') break;
        result += c;
    }
    return result;
}

struct GuestHsearchEntry {
    uint64_t entry_addr = 0;
    uint64_t key_addr = 0;
};

struct GuestHsearchTable {
    bool active = false;
    std::unordered_map<std::string, GuestHsearchEntry> entries;
};

static GuestHsearchTable& global_hsearch_table() {
    static GuestHsearchTable table;
    return table;
}

static GuestHsearchEntry create_guest_hsearch_entry(Emulator& emu, const std::string& key,
                                                    uint64_t data_addr) {
    GuestHsearchEntry entry;
    entry.key_addr = emu.memory().heap().allocate(key.size() + 1, 1);
    entry.entry_addr = emu.memory().heap().allocate(16, 8);
    if (entry.key_addr == 0 || entry.entry_addr == 0) {
        entry = {};
        return entry;
    }
    emu.mem_write(entry.key_addr, key.c_str(), key.size() + 1);
    emu.mem_write(entry.entry_addr, &entry.key_addr, sizeof(entry.key_addr));
    emu.mem_write(entry.entry_addr + 8, &data_addr, sizeof(data_addr));
    return entry;
}

void register_hle_search(HleManager& hle) {
    // ========================================================================
    // Linear search functions
    // ========================================================================

    hle.register_function("lfind", [](Emulator& emu) {
        uint64_t key = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t base = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t nmemb_ptr = get_reg(emu, UC_ARM64_REG_X2);
        size_t size = get_reg(emu, UC_ARM64_REG_X3);
        uint64_t compar = get_reg(emu, UC_ARM64_REG_X4);

        size_t nmemb;
        emu.mem_read(nmemb_ptr, &nmemb, sizeof(nmemb));

        for (size_t i = 0; i < nmemb; i++) {
            uint64_t elem = base + i * size;
            uint64_t result = emu.call_function_safe(compar, {key, elem});
            if ((int32_t)result == 0) {
                set_reg(emu, UC_ARM64_REG_X0, elem);
                return;
            }
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);  // Not found
    });

    hle.register_function("lsearch", [](Emulator& emu) {
        uint64_t key = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t base = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t nmemb_ptr = get_reg(emu, UC_ARM64_REG_X2);
        size_t size = get_reg(emu, UC_ARM64_REG_X3);
        uint64_t compar = get_reg(emu, UC_ARM64_REG_X4);

        size_t nmemb;
        emu.mem_read(nmemb_ptr, &nmemb, sizeof(nmemb));

        for (size_t i = 0; i < nmemb; i++) {
            uint64_t elem = base + i * size;
            uint64_t result = emu.call_function_safe(compar, {key, elem});
            if ((int32_t)result == 0) {
                set_reg(emu, UC_ARM64_REG_X0, elem);
                return;
            }
        }
        // Not found - add element
        uint64_t new_elem = base + nmemb * size;
        std::vector<uint8_t> buf(size);
        emu.mem_read(key, buf.data(), size);
        emu.mem_write(new_elem, buf.data(), size);
        nmemb++;
        emu.mem_write(nmemb_ptr, &nmemb, sizeof(nmemb));
        set_reg(emu, UC_ARM64_REG_X0, new_elem);
    });

    // ========================================================================
    // Binary tree search functions
    // Tree node structure: { void *key (offset 0), node *left (8), node *right (16) }
    // ========================================================================

    // Helper to call guest comparison function
    auto call_compar = [](Emulator& emu, uint64_t compar_addr, uint64_t key1, uint64_t key2) -> int {
        uint64_t result = emu.call_function_safe(compar_addr, {key1, key2});
        return static_cast<int>(static_cast<int64_t>(result));
    };

    // tfind - find node in tree
    hle.register_function("tfind", [call_compar](Emulator& emu) {
        uint64_t key = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t rootp = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t compar = get_reg(emu, UC_ARM64_REG_X2);

        if (rootp == 0) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        uint64_t root;
        emu.mem_read(rootp, &root, 8);

        while (root != 0) {
            uint64_t node_key;
            emu.mem_read(root, &node_key, 8);  // key at offset 0

            int cmp = call_compar(emu, compar, key, node_key);
            if (cmp == 0) {
                set_reg(emu, UC_ARM64_REG_X0, root);
                return;
            } else if (cmp < 0) {
                emu.mem_read(root + 8, &root, 8);  // left at offset 8
            } else {
                emu.mem_read(root + 16, &root, 8);  // right at offset 16
            }
        }

        set_reg(emu, UC_ARM64_REG_X0, 0);  // Not found
    });

    // tsearch - search and insert if not found
    hle.register_function("tsearch", [call_compar](Emulator& emu) {
        uint64_t key = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t rootp = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t compar = get_reg(emu, UC_ARM64_REG_X2);

        if (rootp == 0) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        uint64_t root;
        emu.mem_read(rootp, &root, 8);

        // Empty tree - insert at root
        if (root == 0) {
            uint64_t new_node = emu.memory().heap().allocate(24, 8);
            emu.mem_write(new_node, &key, 8);      // key
            uint64_t null_ptr = 0;
            emu.mem_write(new_node + 8, &null_ptr, 8);   // left = NULL
            emu.mem_write(new_node + 16, &null_ptr, 8);  // right = NULL
            emu.mem_write(rootp, &new_node, 8);  // *rootp = new_node
            set_reg(emu, UC_ARM64_REG_X0, new_node);
            return;
        }

        // Search for insertion point
        uint64_t node = root;

        while (node != 0) {
            uint64_t node_key;
            emu.mem_read(node, &node_key, 8);

            int cmp = call_compar(emu, compar, key, node_key);
            if (cmp == 0) {
                set_reg(emu, UC_ARM64_REG_X0, node);
                return;
            } else if (cmp < 0) {
                uint64_t left;
                emu.mem_read(node + 8, &left, 8);
                if (left == 0) {
                    uint64_t new_node = emu.memory().heap().allocate(24, 8);
                    emu.mem_write(new_node, &key, 8);
                    uint64_t null_ptr = 0;
                    emu.mem_write(new_node + 8, &null_ptr, 8);
                    emu.mem_write(new_node + 16, &null_ptr, 8);
                    emu.mem_write(node + 8, &new_node, 8);
                    set_reg(emu, UC_ARM64_REG_X0, new_node);
                    return;
                }
                node = left;
            } else {
                uint64_t right;
                emu.mem_read(node + 16, &right, 8);
                if (right == 0) {
                    uint64_t new_node = emu.memory().heap().allocate(24, 8);
                    emu.mem_write(new_node, &key, 8);
                    uint64_t null_ptr = 0;
                    emu.mem_write(new_node + 8, &null_ptr, 8);
                    emu.mem_write(new_node + 16, &null_ptr, 8);
                    emu.mem_write(node + 16, &new_node, 8);
                    set_reg(emu, UC_ARM64_REG_X0, new_node);
                    return;
                }
                node = right;
            }
        }

        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // tdelete - delete node from tree
    hle.register_function("tdelete", [call_compar](Emulator& emu) {
        uint64_t key = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t rootp = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t compar = get_reg(emu, UC_ARM64_REG_X2);

        if (rootp == 0) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        uint64_t root;
        emu.mem_read(rootp, &root, 8);
        if (root == 0) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        uint64_t parent_addr = rootp;
        uint64_t node = root;

        while (node != 0) {
            uint64_t node_key;
            emu.mem_read(node, &node_key, 8);

            int cmp = call_compar(emu, compar, key, node_key);
            if (cmp == 0) {
                uint64_t left, right;
                emu.mem_read(node + 8, &left, 8);
                emu.mem_read(node + 16, &right, 8);

                uint64_t replacement;
                if (left == 0) {
                    replacement = right;
                } else if (right == 0) {
                    replacement = left;
                } else {
                    uint64_t succ_parent_addr = node + 16;
                    uint64_t succ = right;
                    uint64_t succ_left;
                    emu.mem_read(succ + 8, &succ_left, 8);
                    while (succ_left != 0) {
                        succ_parent_addr = succ + 8;
                        succ = succ_left;
                        emu.mem_read(succ + 8, &succ_left, 8);
                    }

                    uint64_t succ_key;
                    emu.mem_read(succ, &succ_key, 8);
                    emu.mem_write(node, &succ_key, 8);

                    uint64_t succ_right;
                    emu.mem_read(succ + 16, &succ_right, 8);
                    emu.mem_write(succ_parent_addr, &succ_right, 8);

                    set_reg(emu, UC_ARM64_REG_X0, node);
                    return;
                }

                emu.mem_write(parent_addr, &replacement, 8);
                set_reg(emu, UC_ARM64_REG_X0, parent_addr);
                return;
            } else if (cmp < 0) {
                parent_addr = node + 8;
                emu.mem_read(node + 8, &node, 8);
            } else {
                parent_addr = node + 16;
                emu.mem_read(node + 16, &node, 8);
            }
        }

        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // twalk - walk tree in sorted order
    hle.register_function("twalk", [](Emulator& emu) {
        uint64_t root = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t action = get_reg(emu, UC_ARM64_REG_X1);

        if (root == 0 || action == 0) return;

        // VISIT values: preorder=0, postorder=1, endorder=2, leaf=3
        std::vector<std::pair<uint64_t, int>> stack;
        stack.push_back({root, 0});
        int level = 0;

        while (!stack.empty()) {
            auto& [node, state] = stack.back();

            uint64_t left, right;
            emu.mem_read(node + 8, &left, 8);
            emu.mem_read(node + 16, &right, 8);
            bool is_leaf = (left == 0 && right == 0);

            if (state == 0) {
                if (is_leaf) {
                    emu.call_function_safe(action, {node, 3, static_cast<uint64_t>(level)});
                    stack.pop_back();
                } else {
                    emu.call_function_safe(action, {node, 0, static_cast<uint64_t>(level)});
                    state = 1;
                    if (left != 0) {
                        stack.push_back({left, 0});
                        level++;
                    }
                }
            } else if (state == 1) {
                emu.call_function_safe(action, {node, 1, static_cast<uint64_t>(level)});
                state = 2;
                if (right != 0) {
                    stack.push_back({right, 0});
                    level++;
                }
            } else {
                emu.call_function_safe(action, {node, 2, static_cast<uint64_t>(level)});
                stack.pop_back();
                level--;
            }
        }
    });

    // tdestroy - destroy tree
    hle.register_function("tdestroy", [](Emulator& emu) {
        uint64_t root = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t free_node = get_reg(emu, UC_ARM64_REG_X1);

        if (root == 0) return;

        std::vector<uint64_t> stack;
        std::vector<uint64_t> delete_order;
        stack.push_back(root);

        while (!stack.empty()) {
            uint64_t node = stack.back();
            stack.pop_back();

            delete_order.push_back(node);

            uint64_t left, right;
            emu.mem_read(node + 8, &left, 8);
            emu.mem_read(node + 16, &right, 8);

            if (left != 0) stack.push_back(left);
            if (right != 0) stack.push_back(right);
        }

        for (auto it = delete_order.rbegin(); it != delete_order.rend(); ++it) {
            uint64_t node = *it;
            uint64_t node_key;
            emu.mem_read(node, &node_key, 8);
            if (free_node != 0) {
                emu.call_function_safe(free_node, {node_key});
            }
        }
    });

    // ========================================================================
    // Hash table functions
    // ========================================================================

    // Map from host ENTRY* to guest entry buffer address
    static std::unordered_map<ENTRY*, uint64_t> host_to_guest_entry_r;

    hle.register_function("hcreate", [](Emulator& emu) {
        size_t nel = get_reg(emu, UC_ARM64_REG_X0);
        auto& table = global_hsearch_table();
        table.active = (nel != 0);
        table.entries.clear();
        set_reg(emu, UC_ARM64_REG_X0, table.active ? 1 : 0);
    });

    // hsearch - ARM64 ABI: ENTRY (16 bytes) passed in X0 (key) and X1 (data), action in X2
    hle.register_function("hsearch", [](Emulator& emu) {
        uint64_t guest_key_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t guest_data_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int action = get_reg(emu, UC_ARM64_REG_X2);

        auto& table = global_hsearch_table();
        if (!table.active) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        std::string key = read_string(emu, guest_key_ptr);

        auto it = table.entries.find(key);
        if (it == table.entries.end()) {
            if (action != ENTER) {
                set_reg(emu, UC_ARM64_REG_X0, 0);
                return;
            }

            GuestHsearchEntry entry = create_guest_hsearch_entry(emu, key, guest_data_ptr);
            if (entry.entry_addr == 0) {
                hle_set_errno(emu, ENOMEM);
                set_reg(emu, UC_ARM64_REG_X0, 0);
                return;
            }
            it = table.entries.emplace(key, entry).first;
        }

        if (it != table.entries.end()) {
            set_reg(emu, UC_ARM64_REG_X0, it->second.entry_addr);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    hle.register_function("hdestroy", [](Emulator& emu) {
        auto& table = global_hsearch_table();
        table.entries.clear();
        table.active = false;
    });

    hle.register_function("hcreate_r", [](Emulator& emu) {
        size_t nel = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t htab_ptr = get_reg(emu, UC_ARM64_REG_X1);

        if (!htab_ptr) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        struct hsearch_data htab = {};
        int result = ::hcreate_r(nel, &htab);
        emu.mem_write(htab_ptr, &htab, sizeof(htab));
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("hsearch_r", [](Emulator& emu) {
        uint64_t guest_key_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t guest_data_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int action = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t retval_ptr = get_reg(emu, UC_ARM64_REG_X3);
        uint64_t htab_ptr = get_reg(emu, UC_ARM64_REG_X4);

        if (!htab_ptr) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        struct hsearch_data htab;
        emu.mem_read(htab_ptr, &htab, sizeof(htab));

        std::string key = read_string(emu, guest_key_ptr);

        static std::vector<std::unique_ptr<char[]>> keys;
        keys.push_back(std::make_unique<char[]>(key.size() + 1));
        strcpy(keys.back().get(), key.c_str());

        ENTRY item, *result;
        item.key = keys.back().get();
        item.data = nullptr;

        int rc = ::hsearch_r(item, static_cast<ACTION>(action), &result, &htab);
        emu.mem_write(htab_ptr, &htab, sizeof(htab));

        if (rc && result && retval_ptr) {
            auto it = host_to_guest_entry_r.find(result);
            uint64_t entry_buf;

            if (it != host_to_guest_entry_r.end()) {
                entry_buf = it->second;
            } else {
                entry_buf = emu.memory().heap().allocate(16, 8);
                uint64_t key_addr = emu.memory().heap().allocate(strlen(result->key) + 1, 1);
                emu.mem_write(key_addr, result->key, strlen(result->key) + 1);
                emu.mem_write(entry_buf, &key_addr, 8);
                emu.mem_write(entry_buf + 8, &guest_data_ptr, 8);
                host_to_guest_entry_r[result] = entry_buf;
            }
            emu.mem_write(retval_ptr, &entry_buf, 8);
        } else if (retval_ptr) {
            uint64_t null = 0;
            emu.mem_write(retval_ptr, &null, 8);
        }

        if (!rc && action == FIND) {
            hle_set_errno(emu, ESRCH);
        }

        set_reg(emu, UC_ARM64_REG_X0, rc);
    });

    hle.register_function("hdestroy_r", [](Emulator& emu) {
        uint64_t htab_ptr = get_reg(emu, UC_ARM64_REG_X0);
        if (htab_ptr) {
            struct hsearch_data htab;
            emu.mem_read(htab_ptr, &htab, sizeof(htab));
            ::hdestroy_r(&htab);
        }
    });

    // ========================================================================
    // Queue operations
    // Element format: void* forward_link, void* backward_link, data...
    // ========================================================================

    hle.register_function("insque", [](Emulator& emu) {
        uint64_t elem = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t prev = get_reg(emu, UC_ARM64_REG_X1);

        if (elem == 0) return;

        if (prev == 0) {
            uint64_t null_ptr = 0;
            emu.mem_write(elem + 0, &null_ptr, 8);
            emu.mem_write(elem + 8, &null_ptr, 8);
        } else {
            uint64_t next;
            emu.mem_read(prev + 0, &next, 8);

            emu.mem_write(elem + 0, &next, 8);
            emu.mem_write(elem + 8, &prev, 8);
            emu.mem_write(prev + 0, &elem, 8);
            if (next) {
                emu.mem_write(next + 8, &elem, 8);
            }
        }
    });

    hle.register_function("remque", [](Emulator& emu) {
        uint64_t elem = get_reg(emu, UC_ARM64_REG_X0);

        if (elem == 0) return;

        uint64_t next, prev;
        emu.mem_read(elem + 0, &next, 8);
        emu.mem_read(elem + 8, &prev, 8);

        if (prev) {
            emu.mem_write(prev + 0, &next, 8);
        }
        if (next) {
            emu.mem_write(next + 8, &prev, 8);
        }
    });
}

} // namespace cross_shim
