/*
 * Minimal shim for bionic gtest globals
 */

#pragma once

#include <gtest/gtest.h>
#include <string>

// Get test executable directory
inline std::string GetTestLibRoot() {
    return "/data/local/tmp";
}

// Get path to test data
inline std::string GetTestDataPath(const std::string& name) {
    return "/tmp/" + name;
}
