/*
 * Minimal shim for android-base/silent_death_test.h
 */

#pragma once

#include <gtest/gtest.h>

// SilentDeathTest - base class for tests that expect crashes
// On Android this suppresses logcat spam; we just use regular gtest
using SilentDeathTest = ::testing::Test;

// DeathTest alias
using DeathTest = SilentDeathTest;

// Macro to define a death test class
#define DEATH_TEST_CASE(test_case_name, death_test_name) \
    TEST_F(SilentDeathTest, test_case_name##_##death_test_name)
