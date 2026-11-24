#!/usr/bin/env bash
# mayhem/build.sh — build NuRaft's fuzz harnesses (sanitized) and its unit tests (normal flags).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${ASIO_INCLUDE:=/opt/toolchains/deps/asio-1.24.0/include}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
[ -f "$ASIO_INCLUDE/asio.hpp" ] || { echo "asio headers missing at $ASIO_INCLUDE" >&2; exit 1; }

# Both build dirs live under build/, which upstream's .gitignore already covers.
COMMON_CMAKE=(-DDISABLE_SSL=1 -DBUILD_EXAMPLES=OFF -DASIO_INCLUDE_DIR="$ASIO_INCLUDE")

# 1) Unit tests, project's normal flags (oracle for test.sh).
TESTS=(buffer_test serialization_test strfmt_test raft_server_test snapshot_test
       leader_election_test learner_new_joiner_test failure_test)
cmake -S . -B build/tests -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_TESTING=ON "${COMMON_CMAKE[@]}" \
      -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS"
cmake --build build/tests -j"$MAYHEM_JOBS" --target "${TESTS[@]}"

# 2) The library itself, sanitized + DWARF 3 (custom build type: no -DNDEBUG, so asserts stay on).
# SanCov on the library and harness objects (libFuzzer feedback); linked by $LIB_FUZZING_ENGINE.
FUZZ_NOLINK="${LIB_FUZZING_ENGINE/-fsanitize=fuzzer/-fsanitize=fuzzer-no-link}"
# UBSan's `enum` check is relaxed (only it; ASan and the rest of UBSan stay halting): the RPC
# decoder casts each wire byte to msg_type / log_val_type before validating it with is_valid_msg()
# (asio_service.cxx), so the check fires on every message with an unknown type byte and the
# fuzzer could never get past the first header field. -fno-sanitize is a no-op when
# SANITIZER_FLAGS is empty.
UBSAN_RELAX=""
case "$SANITIZER_FLAGS" in *undefined*) UBSAN_RELAX="-fno-sanitize=enum" ;; esac
FUZZ_CXXFLAGS="-O1 $FUZZ_NOLINK $SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS"
cmake -S . -B build/fuzz -DCMAKE_BUILD_TYPE=Fuzz -DBUILD_TESTING=OFF "${COMMON_CMAKE[@]}" \
      -DCMAKE_CXX_FLAGS="$FUZZ_CXXFLAGS"
cmake --build build/fuzz -j"$MAYHEM_JOBS" --target static_lib
LIB="$SRC/build/fuzz/libnuraft.a"

# 3) Harnesses: libFuzzer binary + standalone reproducer each.
OBJ="$SRC/build/fuzz/harness"
mkdir -p "$OBJ"
INC=(-DASIO_STANDALONE -DSSL_LIBRARY_NOT_FOUND=1 -I"$SRC/include" -I"$SRC/include/libnuraft"
     -I"$SRC/src" -I"$SRC/examples" -I"$ASIO_INCLUDE")
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OBJ/lsan_off.o"
$CXX -std=c++11 $FUZZ_CXXFLAGS "${INC[@]}" -c examples/in_memory_log_store.cxx -o "$OBJ/in_memory_log_store.o"

build_one() {  # <target> <source> [extra cflags]
    local t="$1" src="$2"; shift 2
    $CXX -std=c++11 $FUZZ_CXXFLAGS "${INC[@]}" "$@" -c "$src" -o "$OBJ/$t.o"
    local objs=("$OBJ/$t.o" "$OBJ/in_memory_log_store.o" "$OBJ/lsan_off.o" "$LIB" -lpthread)
    $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${objs[@]}" -o "$SRC/$t"
    $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OBJ/standalone_main.o" "${objs[@]}" -o "$SRC/$t-standalone"
}
build_one fuzz_rpc_request       mayhem/harnesses/fuzz_rpc_request.cc -DFIX_CRC
build_one fuzz_rpc_request_raw   mayhem/harnesses/fuzz_rpc_request.cc
build_one fuzz_cluster_config    mayhem/harnesses/fuzz_cluster_config.cc
build_one fuzz_snapshot_sync_req mayhem/harnesses/fuzz_snapshot_sync_req.cc
build_one fuzz_log_entry_state   mayhem/harnesses/fuzz_log_entry_state.cc
echo "build.sh: done"
