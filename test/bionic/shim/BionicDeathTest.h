/*
 * Minimal shim for bionic death test utilities
 */

#pragma once

#include <gtest/gtest.h>

// SilentDeathTest - base class for tests that expect crashes/exits
// On Android this suppresses logcat spam; we just use regular death tests
using SilentDeathTest = ::testing::Test;

// Macro for expected death with message (use gtest's if available)
#ifndef ASSERT_DEATH_IF_SUPPORTED
#define ASSERT_DEATH_IF_SUPPORTED(statement, regex) \
    GTEST_DEATH_TEST_(statement, regex, GTEST_FATAL_FAILURE_)
#endif

// For tests that should only run on bionic
#if defined(__BIONIC__)
#define TEST_ON_BIONIC(suite, name) TEST(suite, name)
#else
#define TEST_ON_BIONIC(suite, name) TEST(suite, DISABLED_##name)
#endif
