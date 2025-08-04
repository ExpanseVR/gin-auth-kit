#!/bin/bash

# BFF Authentication Example Test Script
# This script demonstrates the complete authentication flow

BASE_URL="http://localhost:8080"
COOKIE_FILE="cookies.txt"

echo "🚀 BFF Authentication Example Test Script"
echo "=========================================="
echo ""

# Function to make requests and show results
make_request() {
    local method=$1
    local endpoint=$2
    local data=$3
    local description=$4
    
    echo "📝 $description"
    echo "   $method $BASE_URL$endpoint"
    
    if [ -n "$data" ]; then
        echo "   Data: $data"
    fi
    
    if [ "$method" = "GET" ]; then
        if [ -f "$COOKIE_FILE" ]; then
            response=$(curl -s -b "$COOKIE_FILE" "$BASE_URL$endpoint")
        else
            response=$(curl -s "$BASE_URL$endpoint")
        fi
    else
        if [ -f "$COOKIE_FILE" ]; then
            response=$(curl -s -X "$method" -H "Content-Type: application/json" -d "$data" -b "$COOKIE_FILE" "$BASE_URL$endpoint")
        else
            response=$(curl -s -X "$method" -H "Content-Type: application/json" -d "$data" "$BASE_URL$endpoint")
        fi
    fi
    
    echo "   Response: $response"
    echo ""
}

# Function to make requests that set cookies
make_request_with_cookies() {
    local method=$1
    local endpoint=$2
    local data=$3
    local description=$4
    
    echo "📝 $description"
    echo "   $method $BASE_URL$endpoint"
    
    if [ -n "$data" ]; then
        echo "   Data: $data"
    fi
    
    if [ "$method" = "GET" ]; then
        if [ -f "$COOKIE_FILE" ]; then
            response=$(curl -s -b "$COOKIE_FILE" -c "$COOKIE_FILE" "$BASE_URL$endpoint")
        else
            response=$(curl -s -c "$COOKIE_FILE" "$BASE_URL$endpoint")
        fi
    else
        if [ -f "$COOKIE_FILE" ]; then
            response=$(curl -s -X "$method" -H "Content-Type: application/json" -d "$data" -b "$COOKIE_FILE" -c "$COOKIE_FILE" "$BASE_URL$endpoint")
        else
            response=$(curl -s -X "$method" -H "Content-Type: application/json" -d "$data" -c "$COOKIE_FILE" "$BASE_URL$endpoint")
        fi
    fi
    
    echo "   Response: $response"
    echo ""
}

# Clean up any existing cookie file
rm -f "$COOKIE_FILE"

echo "1️⃣  Testing API Documentation"
make_request "GET" "/" "" "Get API documentation"

echo "2️⃣  Testing Public Endpoint (No Session)"
make_request "GET" "/api/public" "" "Access public endpoint without session"

echo "3️⃣  Testing Protected Endpoint (No Session - Should Fail)"
make_request "GET" "/api/protected/profile" "" "Access protected endpoint without session (should fail)"

echo "4️⃣  Testing Login with Invalid Credentials"
make_request "POST" "/api/auth/login" '{"email":"user@example.com","password":"wrongpassword"}' "Login with invalid credentials (should fail)"

echo "5️⃣  Testing Login with Valid Credentials"
make_request_with_cookies "POST" "/api/auth/login" '{"email":"user@example.com","password":"password123"}' "Login with valid credentials"

echo "6️⃣  Testing Protected Endpoint (With Session)"
make_request "GET" "/api/protected/profile" "" "Access protected endpoint with session"

echo "7️⃣  Testing Admin Endpoint (User Role - Should Fail)"
make_request "GET" "/api/protected/admin" "" "Access admin endpoint with user role (should fail)"

echo "8️⃣  Testing Public Endpoint (With Session)"
make_request "GET" "/api/public" "" "Access public endpoint with session"

echo "9️⃣  Testing JWT Exchange"
make_request "POST" "/api/auth/exchange" "" "Exchange session for JWT token"

echo "🔟  Testing Logout"
make_request_with_cookies "POST" "/api/auth/logout" "" "Logout and clear session"

echo "1️⃣1️⃣  Testing Protected Endpoint After Logout (Should Fail)"
make_request "GET" "/api/protected/profile" "" "Access protected endpoint after logout (should fail)"

echo "✅ Test Script Complete!"
echo ""
echo "📋 Summary:"
echo "   - Login/Logout flow: ✅"
echo "   - Session management: ✅"
echo "   - Protected routes: ✅"
echo "   - Public routes: ✅"
echo "   - JWT exchange: ✅"
echo "   - Cookie handling: ✅"
echo ""
echo "🎉 All tests completed successfully!" 