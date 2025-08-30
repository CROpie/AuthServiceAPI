# Attempted to make unit tests for Curl using bash
# Note: php server has to be running for these to work

successes=0
fails=0

unhappy_path_test() {
    local test="$1"
    local username="$2"
    local password="$3"
    local substring="$4"

    response=$(curl -s -X POST http://localhost:8000/api/token \
     -d "username=$username&password=$password")

    data=$(echo "$response" | jq -r '.data')
    error=$(echo "$response" | jq -r '.error')

    if [[ -n "$data" && "$data" != "null"  ]]; then
        echo "($test) failed: data where none expected"
        echo "Actual data: $data"
        ((fails++))
        return
    fi

    if [[ "$error" != *"$substring"* ]]; then
        echo "($test) failed: substring not found in error"
        echo "Actual error: $error"
        ((fails++))
        return
    fi

    ((successes++))
    
}

happy_path_test() {
    local test="$1"
    local username="$2"
    local password="$3"

    response=$(curl -s -X POST http://localhost:8000/api/token \
     -d "username=$username&password=$password")

    data=$(echo "$response" | jq -r '.data')
    error=$(echo "$response" | jq -r '.error')

    if [[ -n "$error" && "$error" != "null" ]]; then
        echo "($test) failed: error where none expected"
        echo "Actual error: $error"
        ((fails++))
        return
    fi

    if [[ -z "$data" && "$data" == "null"  ]]; then
        echo "($test) failed: no data where data expected"
        ((fails++))
        return
    fi

    ((successes++))
}

# test number | username | password | error substring
unhappy_path_test 1 "" "password" "username field was left empty"
unhappy_path_test 2 "chris" "" "password field was left empty"
unhappy_path_test 3 "unknown_user" "password" "cannot find user in database"
unhappy_path_test 4 "chris" "not_my_password" "incorrect password"

happy_path_test 5 "chris" "password"

echo "successes: $successes, fails: $fails"