#include "call_graph.hpp"

#include <cstdio>

/* Entry point of the fixture binary. Load the resulting `calltree_sample`
 * executable in Binary Ninja to exercise the Calltree plugin / CallGraph API.
 *
 * main -> run_all -> (chain / diamond / factorial / ping<->pong / leaf_add)
 *
 * `argc` is threaded through run_all so the optimizer cannot fold the program
 * to a constant and drop the call graph. */
int main(int argc, char ** /*argv*/) {
    int total = run_all(argc);
    std::printf("calltree_sample total=%d\n", total);
    return 0;
}
