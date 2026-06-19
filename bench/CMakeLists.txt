# Performance benchmarks: BUILD-ONLY. Built alongside the tests but NOT
# registered as ctest cases (perf-noisy, long-running). Run manually, e.g.
#   ./run ./build/bench_ferret      # two-party, loopback via the run script
#   ./build/bench_lpn               # single-process
# Networked (two boxes): ALICE listens, BOB connects via EMP_PEER_IP; the shared
# port is EMP_PORT (default 12345). Only the party id is a positional arg --
#   A$ ./build/bench_ot_extension 1
#   B$ EMP_PEER_IP=<A's address> ./build/bench_ot_extension 2
#   (EMP_PEER_IP unset => loopback, the default single-box behaviour)
# Timing helpers live in bench/bench.h; these emit throughput only (no asserts).
function(add_bench name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE emp-ot::emp-ot)
    set_target_properties(${name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
endfunction()

add_bench(bench_base_ot)
add_bench(bench_iknp)
add_bench(bench_softspoken)
add_bench(bench_ferret)
add_bench(bench_silentferret)
add_bench(bench_lpn)
add_bench(bench_cggm)
add_bench(bench_ot_extension)
add_bench(bench_f2k_vole)
add_bench(bench_fp_vole)
