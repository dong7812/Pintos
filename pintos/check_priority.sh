#!/bin/bash

# --- CONFIGURATION ---
# (이 스크립트는 /pintos/ 폴더에 있다고 가정합니다)
THREADS_DIR="threads"
BUILD_DIR="threads/build"

# (여기에 원하는 테스트만 추가/삭제하세요)
TESTS_TO_RUN=(
    "tests/threads/alarm-single"
    "tests/threads/alarm-multiple"
    "tests/threads/alarm-negative"
    "tests/threads/alarm-priority"
    "tests/threads/alarm-simultaneous"
    "tests/threads/alarm-zero"
    "tests/threads/priority-change"
    "tests/threads/priority-donate-one"
    "tests/threads/priority-donate-multiple"
    "tests/threads/priority-donate-multiple2"
    "tests/threads/priority-donate-nest"
    "tests/threads/priority-preempt"
    "tests/threads/priority-fifo"
    "tests/threads/priority-sema"
    "tests/threads/priority-condvar"
)
# --- END CONFIGURATION ---


# 0. 스크립트가 올바른 위치(pintos)에서 실행되었는지 확인
if [ ! -d "$THREADS_DIR" ]; then
    echo "Error: This script must be run from the 'pintos' root directory."
    echo "Failed to find directory: $THREADS_DIR"
    exit 1
fi

# 1. Move to build directory
# (사용자가 make clean과 make를 수동으로 실행했다고 가정)
echo "Moving to $BUILD_DIR..."
if [ ! -d "$BUILD_DIR" ]; then
    echo "Error: Build directory '$BUILD_DIR' not found."
    echo "Please run 'make' in '$THREADS_DIR' first."
    exit 1
fi

# build 디렉토리로 이동합니다.
cd $BUILD_DIR
echo "Now in $(pwd)"


# 2. Run all specified tests
# (make 명령어는 build 디렉토리 내부에서 실행되어야 합니다)
echo "========================================"
echo "Running all specified priority tests..."
echo "(This may take a moment. Raw pintos output is suppressed.)"
echo "========================================"
for TEST_NAME in "${TESTS_TO_RUN[@]}"; do
    echo "--- Running $TEST_NAME ---"
    
    # stdout과 stderr를 모두 /dev/null로 리디렉션하여 숨깁니다.
    make "${TEST_NAME}.result" &> /dev/null
done


# 3. Check all results (Simplified Summary)
echo "========================================"
echo "Checking results..."
echo "========================================"
ALL_PASSED=true

for TEST_NAME in "${TESTS_TO_RUN[@]}"; do
    TEST_FILE="${TEST_NAME}.result"

    if [ -f "$TEST_FILE" ]; then
        # FAIL이 있는지 확인
        if grep -q "FAIL" "$TEST_FILE"; then
            ALL_PASSED=false
            echo "TEST: $TEST_FILE (FAILED ❌)"
            # ⭐️ FIX: 상세 로그(output, errors)를 출력하지 않습니다.
        else
            echo "TEST: $TEST_FILE (PASSED ✅)"
        fi
    else
        # .result 파일 자체가 생성 안 된 경우 (make 오류)
        ALL_PASSED=false
        echo "TEST: $TEST_FILE (ERROR ❗️ - Result file not found)"
    fi
done

echo "========================================"
if $ALL_PASSED; then
    echo "All specified tests passed! 🎉"
else
    echo "Some tests failed or failed to run."
fi

# 4. Go back to the original directory (pintos root)
cd ../..
echo "Returning to $(pwd)"