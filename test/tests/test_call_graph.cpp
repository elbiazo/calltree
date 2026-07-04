/* C++ unit tests validating that the fixture call graph behaves exactly as
 * documented in call_graph.hpp. These runtime checks guarantee every function
 * is genuinely exercised (so the compiler keeps the calls), which is what makes
 * `calltree_sample` a faithful fixture for the Calltree plugin.
 *
 * Each TEST_CASE below corresponds to a subgraph the plugin's CallGraph API is
 * expected to reproduce (see test/README.md for the API mapping).
 */
#include "test_framework.hpp"

#include "call_graph.hpp"

/* leaf_add: pure leaf. */
TEST_CASE(leaf) {
    CHECK_EQ(leaf_add(2, 3), 5);
    CHECK_EQ(leaf_add(-1, 1), 0);
}

/* chain_a -> chain_b -> chain_c -> leaf_add. */
TEST_CASE(callers_chain) {
    CHECK_EQ(chain_c(1), 2); /* leaf_add(1, 1) */
    CHECK_EQ(chain_b(1), 4); /* chain_c(1) * 2 */
    CHECK_EQ(chain_a(1), 7); /* chain_b(1) + 3 */
}

/* diamond_top -> {left, right} -> bottom -> leaf_add ; top(n) == 2n + 3. */
TEST_CASE(diamond_paths) {
    CHECK_EQ(diamond_bottom(2), 2);
    CHECK_EQ(diamond_left(2), 3);
    CHECK_EQ(diamond_right(2), 4);
    CHECK_EQ(diamond_top(2), 7);
}

/* Self recursion. */
TEST_CASE(factorial) {
    CHECK_EQ(factorial(0), 1);
    CHECK_EQ(factorial(1), 1);
    CHECK_EQ(factorial(5), 120);
}

/* Mutual recursion ping <-> pong ; ping(n) == pong(n) == n. */
TEST_CASE(mutual_recursion) {
    CHECK_EQ(ping(0), 0);
    CHECK_EQ(ping(5), 5);
    CHECK_EQ(pong(4), 4);
}

/* Aggregating entry point. run_all(1) = 7 + 5 + 120 + 1 + 2 = 135. */
TEST_CASE(run_all) {
    CHECK_EQ(::run_all(1), 135);
    CHECK(::run_all(3) > 0);
}

int main(int argc, char **argv) {
    return tf::main_impl(argc, argv);
}
