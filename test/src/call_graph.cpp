#include "call_graph.hpp"

/* See call_graph.hpp for the intended call-graph shape. Every function below
 * makes only *direct* calls so the edges are visible in Binary Ninja. */

int leaf_add(int a, int b) {
    return a + b;
}

/* chain_a -> chain_b -> chain_c -> leaf_add */
int chain_c(int n) {
    return leaf_add(n, 1);      /* n + 1 */
}
int chain_b(int n) {
    return chain_c(n) * 2;      /* 2n + 2 */
}
int chain_a(int n) {
    return chain_b(n) + 3;      /* 2n + 5 */
}

/* diamond_top -> {diamond_left, diamond_right} -> diamond_bottom -> leaf_add */
int diamond_bottom(int n) {
    return leaf_add(n, 0);      /* n */
}
int diamond_left(int n) {
    return diamond_bottom(n) + 1;
}
int diamond_right(int n) {
    return diamond_bottom(n) + 2;
}
int diamond_top(int n) {
    return diamond_left(n) + diamond_right(n);  /* 2n + 3 */
}

/* Self recursion. */
int factorial(int n) {
    if (n <= 1) {
        return 1;
    }
    return n * factorial(n - 1);
}

/* Mutual recursion: ping(n) == n, pong(n) == n, terminating at 0. */
int ping(int n) {
    if (n <= 0) {
        return 0;
    }
    return 1 + pong(n - 1);
}
int pong(int n) {
    if (n <= 0) {
        return 0;
    }
    return 1 + ping(n - 1);
}

/* Touches every subgraph; `seed` threads through so nothing constant-folds. */
int run_all(int seed) {
    int total = 0;
    total += chain_a(seed);
    total += diamond_top(seed);
    total += factorial(5);
    total += ping(seed & 7);
    total += leaf_add(seed, 1);
    return total;
}
