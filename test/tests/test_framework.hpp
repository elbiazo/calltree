/* Tiny zero-dependency C++ test framework (doctest-style, no external deps).
 *
 * Usage:
 *   TEST_CASE(name) { CHECK(expr); CHECK_EQ(a, b); }
 *   int main(int argc, char** argv) { return tf::main_impl(argc, argv); }
 *
 * CLI:
 *   <exe>                run all test cases
 *   <exe> --list         print every registered test-case name
 *   <exe> --run NAME     run only the named test case
 *
 * Returns 0 if all selected cases pass, 1 on failure, 2 on bad --run name.
 */
#ifndef CALLTREE_TEST_FRAMEWORK_HPP
#define CALLTREE_TEST_FRAMEWORK_HPP

#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

namespace tf {

struct TestCase {
    std::string name;
    std::function<void(int &)> fn;
};

inline std::vector<TestCase> &registry() {
    static std::vector<TestCase> r;
    return r;
}

struct Registrar {
    Registrar(const char *name, std::function<void(int &)> fn) {
        registry().push_back({name, std::move(fn)});
    }
};

inline int run(const std::string *only) {
    int failures = 0;
    int ran = 0;
    for (auto &tc : registry()) {
        if (only && tc.name != *only) {
            continue;
        }
        int local = 0;
        ++ran;
        tc.fn(local);
        if (local) {
            std::printf("[FAIL] %s (%d check(s) failed)\n", tc.name.c_str(), local);
            ++failures;
        } else {
            std::printf("[ OK ] %s\n", tc.name.c_str());
        }
    }
    if (only && ran == 0) {
        std::printf("[ERR] no such test case: %s\n", only->c_str());
        return 2;
    }
    std::printf("\n%d/%d test case(s) passed\n", ran - failures, ran);
    return failures ? 1 : 0;
}

inline int main_impl(int argc, char **argv) {
    if (argc >= 2 && std::strcmp(argv[1], "--list") == 0) {
        for (auto &tc : registry()) {
            std::printf("%s\n", tc.name.c_str());
        }
        return 0;
    }
    if (argc >= 3 && std::strcmp(argv[1], "--run") == 0) {
        std::string name = argv[2];
        return run(&name);
    }
    return run(nullptr);
}

} // namespace tf

#define TEST_CASE(NAME)                                                        \
    static void NAME##_body(int &_failures);                                   \
    static ::tf::Registrar NAME##_registrar(#NAME, NAME##_body);               \
    static void NAME##_body(int &_failures)

#define CHECK(EXPR)                                                            \
    do {                                                                       \
        if (!(EXPR)) {                                                         \
            ++_failures;                                                       \
            std::printf("    CHECK failed: %s (line %d)\n", #EXPR, __LINE__);  \
        }                                                                      \
    } while (0)

#define CHECK_EQ(A, B)                                                         \
    do {                                                                       \
        auto _a = (A);                                                         \
        auto _b = (B);                                                         \
        if (!(_a == _b)) {                                                     \
            ++_failures;                                                       \
            std::printf("    CHECK_EQ failed: %s == %s (line %d)\n", #A, #B,   \
                        __LINE__);                                             \
        }                                                                      \
    } while (0)

#endif /* CALLTREE_TEST_FRAMEWORK_HPP */
