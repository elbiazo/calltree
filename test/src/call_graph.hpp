/* Deliberately-structured call graph used as a fixture for the Calltree plugin.
 *
 * All functions use C linkage so Binary Ninja shows clean, stable symbol names
 * (leaf_add, chain_a, ping, ...). The structure is intentionally varied so it
 * exercises every part of the CallGraph Python API:
 *
 *   leaf:      leaf_add                      (a pure leaf; callers test target)
 *   chain:     chain_a -> chain_b -> chain_c -> leaf_add
 *   diamond:   diamond_top -> diamond_left  -> diamond_bottom -> leaf_add
 *                          -> diamond_right -> diamond_bottom          (two paths)
 *   self-rec:  factorial -> factorial                                   (self cycle)
 *   mutual:    ping <-> pong                                            (A->B->A cycle)
 *   entry:     run_all -> {chain_a, diamond_top, factorial, ping, leaf_add}
 *
 * Compiled with -O0 -fno-inline (see CMakeLists.txt) so the calls survive as
 * authored and match what the plugin extracts.
 */
#ifndef CALLTREE_TEST_CALL_GRAPH_HPP
#define CALLTREE_TEST_CALL_GRAPH_HPP

#ifdef __cplusplus
extern "C" {
#endif

/* Pure leaf: calls nothing. */
int leaf_add(int a, int b);

/* Linear chain: chain_a -> chain_b -> chain_c -> leaf_add. */
int chain_c(int n);
int chain_b(int n);
int chain_a(int n);

/* Diamond: two distinct paths from diamond_top down to diamond_bottom. */
int diamond_bottom(int n);
int diamond_left(int n);
int diamond_right(int n);
int diamond_top(int n);

/* Self recursion. */
int factorial(int n);

/* Mutual recursion (the A->B->A cycle the plugin's guard must handle). */
int ping(int n);
int pong(int n);

/* Aggregating entry point that touches every subgraph above. */
int run_all(int seed);

#ifdef __cplusplus
}
#endif

#endif /* CALLTREE_TEST_CALL_GRAPH_HPP */
