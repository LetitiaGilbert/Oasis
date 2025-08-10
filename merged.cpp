#include <iostream>
#include <string>
#include <curl/curl.h>
#include "json.hpp"  // nlohmann::json header
#include <thread>    // for sleep_for
#include <chrono>    // for system_clock, seconds
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>
#include <memory>

using json = nlohmann::json;

// === Utility: collect curl response ===
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// === HTTP Client for blockchain interactions ===
class EthereumRPC {
private:
    std::string rpc_url;
    CURL* curl;

    static size_t WriteCallbackStatic(void* contents, size_t size, size_t nmemb, std::string* response) {
        size_t totalSize = size * nmemb;
        response->append((char*)contents, totalSize);
        return totalSize;
    }

public:
    EthereumRPC(const std::string& url) : rpc_url(url) {
        curl = curl_easy_init();
        if (!curl) {
            throw std::runtime_error("Failed to initialize CURL");
        }
    }

    ~EthereumRPC() {
        if (curl) curl_easy_cleanup(curl);
    }

    json call(const std::string& method, const json& params) {
        json request = {{"jsonrpc", "2.0"}, {"method", method}, {"params", params}, {"id", 1}};

        std::string request_str = request.dump();
        std::string response;

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, rpc_url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_str.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallbackStatic);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        CURLcode res = curl_easy_perform(curl);
        curl_slist_free_all(headers);

        if (res != CURLE_OK) {
            throw std::runtime_error("CURL request failed: " + std::string(curl_easy_strerror(res)));
        }

        return json::parse(response);
    }
};

// === Compatibility function for legacy code ===
json json_rpc_call(const std::string& rpc_url, const json& request) {
    CURL* curl = curl_easy_init();
    std::string readBuffer;
    json result;

    if(curl) {
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        std::string req_str = request.dump();

        curl_easy_setopt(curl, CURLOPT_URL, rpc_url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req_str.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        CURLcode res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << "\n";
        } else {
            try {
                result = json::parse(readBuffer);
            } catch (...) {
                std::cerr << "Failed to parse JSON response\n";
            }
        }
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    return result;
}

// === Utility functions for encoding ===
std::string encodeUint256(uint64_t value) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(64) << value;
    return ss.str();
}

std::string encodeAddress(const std::string& address) {
    std::string clean_addr = address;
    if (clean_addr.substr(0, 2) == "0x") {
        clean_addr = clean_addr.substr(2);
    }
    return std::string(24, '0') + clean_addr;  // Pad to 32 bytes
}

uint64_t hexToUint64(const std::string& hex) {
    std::string cleanHex = hex;
    if (cleanHex.substr(0, 2) == "0x") {
        cleanHex = cleanHex.substr(2);
    }
    if (cleanHex.empty() || cleanHex == "0" ||
        cleanHex.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) {
        return 0;  // Return 0 for invalid or empty hex
    }
    try {
        return std::stoull(cleanHex, nullptr, 16);
    } catch (const std::exception& e) {
        std::cerr << "Warning: Failed to parse hex value '" << hex << "': " << e.what() << std::endl;
        return 0;
    }
}

// === Legacy helper functions ===
std::string to_hex(uint64_t val) {
    char buf[20];
    snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)val);
    return std::string(buf);
}

std::string read_private_key_from_file(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to open private key file: " << filename << std::endl;
        return "";
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string key = buffer.str();
    // Remove any trailing newline or whitespace
    key.erase(key.find_last_not_of(" \n\r\t") + 1);
    return key;
}

std::string encode_balanceOf(const std::string& wallet_address) {
    std::string method_id = "0x70a08231";
    std::string addr = wallet_address;
    if (addr.substr(0, 2) == "0x") addr = addr.substr(2);
    while (addr.size() < 64) addr = "0" + addr;
    return method_id + addr;
}

std::string encode_get_dy(int i, int j, uint64_t dx) {
    std::string method_id = "0x6c0e2e1a";
    auto pad_32bytes = [](uint64_t val) -> std::string {
        char buf[65];
        snprintf(buf, sizeof(buf), "%064llx", (unsigned long long)val);
        return std::string(buf);
    };
    std::string i_enc = pad_32bytes(i);
    std::string j_enc = pad_32bytes(j);
    std::string dx_enc = pad_32bytes(dx);
    return method_id + i_enc + j_enc + dx_enc;
}

std::string encode_exchange(int i, int j, uint64_t dx, uint64_t min_dy) {
    std::string method_id = "0x3df02124"; // keccak256("exchange(int128,int128,uint256,uint256)") first 4 bytes
    auto pad_32bytes = [](uint64_t val) -> std::string {
        char buf[65];
        snprintf(buf, sizeof(buf), "%064llx", (unsigned long long)val);
        return std::string(buf);
    };
    std::string i_enc = pad_32bytes(i);
    std::string j_enc = pad_32bytes(j);
    std::string dx_enc = pad_32bytes(dx);
    std::string min_dy_enc = pad_32bytes(min_dy);
    return method_id + i_enc + j_enc + dx_enc + min_dy_enc;
}

uint64_t hex_to_uint64(const std::string& hex) {
    uint64_t val = 0;
    sscanf(hex.c_str(), "0x%llx", &val);
    return val;
}

// === Simulated price function ===
uint64_t get_dy_simulated(uint64_t amount_in) {
    return static_cast<uint64_t>(amount_in * 0.995);
}

// === Get nonce of wallet ===
uint64_t get_nonce(const std::string& rpc_url, const std::string& wallet_address) {
    json request = {
        {"jsonrpc", "2.0"},
        {"id", 1},
        {"method", "eth_getTransactionCount"},
        {"params", {wallet_address, "pending"}}
    };
    json response = json_rpc_call(rpc_url, request);
    if (response.contains("result")) {
        try {
            return std::stoull(response["result"].get<std::string>().substr(2), nullptr, 16);
        } catch (...) {
            std::cerr << "Failed to parse nonce\n";
        }
    }
    return 0;
}

// === Stub for signing tx (replace with real implementation) ===
std::string sign_transaction(const json& tx, const std::string& private_key) {
    // TODO: Implement RLP encoding + secp256k1 signing
    // For now, return empty string to indicate no signature
    std::cerr << "[Warning] sign_transaction() not implemented. Please implement signing.\n";
    return "";
}

// === Send signed raw transaction ===
json send_raw_transaction(const std::string& rpc_url, const std::string& signed_tx_hex) {
    json request = {
        {"jsonrpc", "2.0"},
        {"id", 1},
        {"method", "eth_sendRawTransaction"},
        {"params", {signed_tx_hex}}
    };
    return json_rpc_call(rpc_url, request);
}

// === ERC20 Token interface ===
class ERC20Token {
private:
    std::string token_address;
    EthereumRPC* rpc;

public:
    ERC20Token(const std::string& address, EthereumRPC* ethereum_rpc)
        : token_address(address), rpc(ethereum_rpc) {
    }

    uint64_t balanceOf(const std::string& account) {
        // Function signature for balanceOf(address) - 0x70a08231
        std::string function_signature = "0x70a08231";
        std::string call_data = function_signature + encodeAddress(account);

        json call_params = {{{"to", token_address}, {"data", call_data}}, "latest"};

        auto result = rpc->call("eth_call", call_params);

        if (result.contains("error")) {
            throw std::runtime_error("RPC Error: " + result["error"]["message"].get<std::string>());
        }

        return hexToUint64(result["result"]);
    }

    std::string transfer(const std::string& to, uint64_t amount, const std::string& from_private_key) {
        // Function signature for transfer(address,uint256) - 0xa9059cbb
        std::string function_signature = "0xa9059cbb";
        std::string call_data = function_signature + encodeAddress(to) + encodeUint256(amount);

        // In a real implementation, you would:
        // 1. Build the transaction
        // 2. Sign it with the private key
        // 3. Send via eth_sendRawTransaction

        std::cout << "MOCK: Transferring " << amount << " tokens to " << to << std::endl;
        std::cout << "Call data: " << call_data << std::endl;

        return "0x" + std::string(64, 'a');  // Mock transaction hash
    }

    std::string approve(const std::string& spender, uint64_t amount, const std::string& from_private_key) {
        // Function signature for approve(address,uint256) - 0x095ea7b3
        std::string function_signature = "0x095ea7b3";
        std::string call_data = function_signature + encodeAddress(spender) + encodeUint256(amount);

        std::cout << "MOCK: Approving " << spender << " to spend " << amount << " tokens" << std::endl;
        std::cout << "Call data: " << call_data << std::endl;

        return "0x" + std::string(64, 'b');  // Mock transaction hash
    }

    std::string getAddress() const {
        return token_address;
    }
};

// === Curve Pool interface ===
class CurvePool {
private:
    std::string pool_address;
    EthereumRPC* rpc;

public:
    CurvePool(const std::string& address, EthereumRPC* ethereum_rpc)
        : pool_address(address), rpc(ethereum_rpc) {
    }

    // Get exchange rate (how much output for given input)
    uint64_t get_dy(int32_t i, int32_t j, uint64_t dx) {
        // Function signature for get_dy(int128,int128,uint256) - 0x5e0d443f
        std::string function_signature = "0x5e0d443f";

        // Encode parameters
        std::string encoded_i = encodeUint256(static_cast<uint64_t>(i));
        std::string encoded_j = encodeUint256(static_cast<uint64_t>(j));
        std::string encoded_dx = encodeUint256(dx);

        std::string call_data = function_signature + encoded_i + encoded_j + encoded_dx;

        json call_params = {{{"to", pool_address}, {"data", call_data}}, "latest"};

        auto result = rpc->call("eth_call", call_params);

        if (result.contains("error")) {
            throw std::runtime_error("RPC Error: " + result["error"]["message"].get<std::string>());
        }

        return hexToUint64(result["result"]);
    }

    // Traditional exchange method (requires approval)
    std::string exchange(
        int32_t i,
        int32_t j,
        uint64_t dx,
        uint64_t min_dy,
        const std::string& receiver,
        const std::string& private_key) {
        // Function signature for exchange(int128,int128,uint256,uint256,address) - 0x394747c5
        std::string function_signature = "0x394747c5";

        std::string call_data = function_signature + encodeUint256(static_cast<uint64_t>(i)) +
                                encodeUint256(static_cast<uint64_t>(j)) + encodeUint256(dx) +
                                encodeUint256(min_dy) + encodeAddress(receiver);

        std::cout << "MOCK: Executing exchange(" << i << ", " << j << ", " << dx << ", " << min_dy
                  << ")" << std::endl;
        std::cout << "Call data: " << call_data << std::endl;

        return "0x" + std::string(64, 'c');  // Mock transaction hash
    }

    // Modern exchange_received method (no approval needed)
    std::string exchange_received(
        int32_t i,
        int32_t j,
        uint64_t dx,
        uint64_t min_dy,
        const std::string& receiver,
        const std::string& private_key) {
        // Function signature for exchange_received(int128,int128,uint256,uint256,address) - 0x15bf4c40
        std::string function_signature = "0x15bf4c40";  // Mock signature for exchange_received

        std::string call_data = function_signature + encodeUint256(static_cast<uint64_t>(i)) +
                                encodeUint256(static_cast<uint64_t>(j)) + encodeUint256(dx) +
                                encodeUint256(min_dy) + encodeAddress(receiver);

        std::cout << "MOCK: Executing exchange_received(" << i << ", " << j << ", " << dx << ", "
                  << min_dy << ")" << std::endl;
        std::cout << "Call data: " << call_data << std::endl;

        return "0x" + std::string(64, 'd');  // Mock transaction hash
    }

    std::string getAddress() const {
        return pool_address;
    }
};

// === Curve Meta Registry interface ===
class CurveMetaRegistry {
private:
    std::string registry_address;
    EthereumRPC* rpc;

public:
    CurveMetaRegistry(const std::string& address, EthereumRPC* ethereum_rpc)
        : registry_address(address), rpc(ethereum_rpc) {
    }

    // Find pool for token pair
    std::string find_pool_for_coins(const std::string& from_token, const std::string& to_token) {
        // Function signature for find_pool_for_coins(address,address) - simplified
        std::string function_signature = "0xa87df06c";

        std::string call_data =
            function_signature + encodeAddress(from_token) + encodeAddress(to_token);

        json call_params = {{{"to", registry_address}, {"data", call_data}}, "latest"};

        auto result = rpc->call("eth_call", call_params);

        if (result.contains("error")) {
            throw std::runtime_error("RPC Error: " + result["error"]["message"].get<std::string>());
        }

        std::string hex_result = result["result"];
        if (hex_result.length() >= 66) {
            return "0x" + hex_result.substr(hex_result.length() - 40);
        }

        return "";
    }

    // Get exchange amount estimate
    uint64_t get_exchange_amount(
        const std::string& pool,
        const std::string& from_token,
        const std::string& to_token,
        uint64_t amount) {
        // Simplified implementation
        std::cout << "Getting exchange amount for pool: " << pool << std::endl;
        std::cout << "From: " << from_token << " To: " << to_token << " Amount: " << amount
                  << std::endl;

        // In reality, this would call the registry's get_exchange_amount function
        return amount * 99 / 100;  // Mock 1% slippage
    }
};

// === Time-in-force policies enum & LimitOrder struct ===
enum class TimeInForce { GTC, GTT, IOC, FOK };

struct LimitOrder {
    std::string input_token;
    uint64_t input_amount;
    std::string output_token;
    double limit_price;
    double slippage_tolerance;
    TimeInForce tif;
    std::chrono::system_clock::time_point expiry_time;
};

// === Get current price ===
double get_current_price(const LimitOrder& order, const std::string& rpc_url,
                         const std::string& curve_pool_contract,
                         int token_in_index, int token_out_index) {
    uint64_t dy = 0;
    if (curve_pool_contract.empty()) {
        dy = get_dy_simulated(order.input_amount);
    } else {
        std::string data = encode_get_dy(token_in_index, token_out_index, order.input_amount);
        json request = {
            {"jsonrpc", "2.0"},
            {"id", 1},
            {"method", "eth_call"},
            {"params", {{
                {"to", curve_pool_contract},
                {"data", data}
            }, "latest"}}
        };

        json response = json_rpc_call(rpc_url, request);
        if (!response.contains("result")) {
            std::cerr << "[Order] Error: no result from get_dy call\n";
            return 0.0;
        }
        std::string out_hex = response["result"];
        if (out_hex.size() < 3) {
            std::cerr << "[Order] Invalid get_dy result: " << out_hex << std::endl;
            return 0.0;
        }
        try {
            dy = std::stoull(out_hex.substr(2), nullptr, 16);
        } catch (const std::exception& e) {
            std::cerr << "[Order] Conversion error for get_dy: " << e.what() << std::endl;
            return 0.0;
        }
    }
    return static_cast<double>(dy) / order.input_amount;
}

// === Execute limit order with swap integration ===
bool execute_limit_order(const LimitOrder& order, const std::string& rpc_url, const std::string& curve_pool_contract,
                         int token_in_index, int token_out_index,
                         const std::string& wallet_address, const std::string& private_key) {
    auto now = std::chrono::system_clock::now();

    if (order.tif == TimeInForce::GTT && now > order.expiry_time) {
        std::cout << "[Order] GTT order expired\n";
        return false;
    }

    double current_price = get_current_price(order, rpc_url, curve_pool_contract, token_in_index, token_out_index);
    if (current_price == 0.0) {
        std::cout << "[Order] Failed to fetch price, will retry...\n";
        return false;
    }

    double min_acceptable_price = order.limit_price * (1 - order.slippage_tolerance);

    std::cout << "[Order] Current price: " << current_price << ", Min acceptable price: " << min_acceptable_price << std::endl;

    bool price_met = (current_price >= min_acceptable_price);
    if (!price_met) {
        switch (order.tif) {
            case TimeInForce::GTC:
                std::cout << "[Order] GTC price not met, retrying...\n";
                return false;
            case TimeInForce::GTT:
                std::cout << "[Order] GTT price not met, retrying...\n";
                return false;
            case TimeInForce::IOC:
                std::cout << "[Order] IOC price not met, canceling order.\n";
                return false;
            case TimeInForce::FOK:
                std::cout << "[Order] FOK cannot fill entire order at limit price, canceling.\n";
                return false;
            default:
                std::cerr << "[Order] Unknown TIF policy\n";
                return false;
        }
    }

    std::cout << "[Order] Price met, preparing to execute swap...\n";

    if (curve_pool_contract.empty()) {
        std::cout << "[Order] Curve pool contract not set, skipping swap execution. Pretending order executed.\n";
        return true;
    }

    // Calculate minimum acceptable dy for slippage protection
    uint64_t min_dy = static_cast<uint64_t>(order.input_amount * min_acceptable_price);

    // Encode swap call data
    std::string swap_data = encode_exchange(token_in_index, token_out_index, order.input_amount, min_dy);

    // Get nonce
    uint64_t nonce = get_nonce(rpc_url, wallet_address);
    std::cout << "[Order] Using nonce: " << nonce << std::endl;

    // Build transaction JSON (simple version, gas and gasPrice should be adjusted!)
    json tx = {
        {"to", curve_pool_contract},
        {"data", swap_data},
        {"nonce", to_hex(nonce)},
        {"gas", to_hex(200000)},       // example gas limit
        {"gasPrice", to_hex(20000000000ULL)}, // 20 Gwei
        {"value", "0x0"},
        {"chainId", 11155111}          // Sepolia chain id
    };

    // Sign the transaction
    std::string signed_tx = sign_transaction(tx, private_key);
    if (signed_tx.empty()) {
        std::cerr << "[Order] Transaction signing failed or not implemented.\n";
        return false;
    }

    // Send signed transaction
    json send_resp = send_raw_transaction(rpc_url, signed_tx);

    if (send_resp.contains("result")) {
        std::cout << "[Order] Swap transaction sent! Tx hash: " << send_resp["result"] << std::endl;
        return true;
    } else {
        std::cerr << "[Order] Failed to send swap transaction: " << send_resp.dump() << std::endl;
        return false;
    }
}

// === Print balances functions ===
void print_eth_balance(const std::string& rpc_url, const std::string& wallet) {
    json request = {
        {"jsonrpc", "2.0"},
        {"id", 1},
        {"method", "eth_getBalance"},
        {"params", {wallet, "latest"}}
    };
    json response = json_rpc_call(rpc_url, request);
    std::cout << "ETH balance RPC response: " << response.dump(2) << std::endl;
    if (!response.contains("result")) {
        std::cerr << "No 'result' field in ETH balance RPC response\n";
        return;
    }
    std::string balance_hex = response["result"];
    if (balance_hex == "0x" || balance_hex == "0x0") {
        std::cout << "ETH balance: 0 ETH\n";
        return;
    }
    try {
        uint64_t balance_wei = std::stoull(balance_hex.substr(2), nullptr, 16);
        double balance_eth = static_cast<double>(balance_wei) / 1e18;
        std::cout << "ETH balance: " << balance_eth << " ETH\n";
    } catch (const std::exception& e) {
        std::cerr << "Error parsing ETH balance: " << e.what() << std::endl;
    }
}

void print_erc20_balance(const std::string& rpc_url, const std::string& wallet, const std::string& erc20_contract) {
    std::string data = encode_balanceOf(wallet);
    json request = {
        {"jsonrpc", "2.0"},
        {"id", 2},
        {"method", "eth_call"},
        {"params", {{
            {"to", erc20_contract},
            {"data", data}
        }, "latest"}}
    };
    json response = json_rpc_call(rpc_url, request);
    if (!response.contains("result")) {
        std::cerr << "No 'result' field in ERC20 balance RPC response\n";
        return;
    }
    std::string balance_hex = response["result"];
    if (balance_hex == "0x" || balance_hex == "0x0") {
        std::cout << "ERC20 token balance: 0\n";
        return;
    }
    try {
        uint64_t balance = std::stoull(balance_hex.substr(2), nullptr, 16);
        double balance_token = static_cast<double>(balance) / 1e6;
        std::cout << "ERC20 token balance: " << balance_token << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Error parsing ERC20 balance: " << e.what() << std::endl;
    }
}

// === High-level Curve Swapper ===
class CurveSwapper {
private:
    EthereumRPC* rpc;
    std::unique_ptr<CurveMetaRegistry> registry;
    std::string user_address;
    std::string private_key;

public:
    CurveSwapper(EthereumRPC* ethereum_rpc, const std::string& user_addr, const std::string& priv_key)
        : rpc(ethereum_rpc), user_address(user_addr), private_key(priv_key) {

        // Initialize Meta Registry
        const std::string METAREGISTRY = "0xF98B45FA17DE75FB1aD0e7aFD971b0ca00e379fC";
        registry = std::make_unique<CurveMetaRegistry>(METAREGISTRY, rpc);
    }

    // Method 1: Traditional exchange with approval
    std::string swapWithApproval(
        const std::string& from_token_addr,
        const std::string& to_token_addr,
        uint64_t amount,
        double slippage_tolerance = 0.01) {

        std::cout << "\n=== Traditional Swap with Approval ===" << std::endl;

        // 1. Find suitable pool
        std::string pool_addr = registry->find_pool_for_coins(from_token_addr, to_token_addr);
        if (pool_addr.empty()) {
            throw std::runtime_error("No pool found for token pair");
        }

        std::cout << "Found pool: " << pool_addr << std::endl;

        // 2. Create token and pool instances
        ERC20Token from_token(from_token_addr, rpc);
        CurvePool pool(pool_addr, rpc);

        // 3. Check balance
        uint64_t balance = from_token.balanceOf(user_address);
        if (balance < amount) {
            throw std::runtime_error("Insufficient balance");
        }

        // 4. Get expected output with slippage protection
        uint64_t expected_output = pool.get_dy(0, 1, amount);  // Assuming indices 0->1
        uint64_t min_output = static_cast<uint64_t>(expected_output * (1.0 - slippage_tolerance));

        std::cout << "Expected output: " << expected_output << std::endl;
        std::cout << "Minimum output (with slippage): " << min_output << std::endl;

        // 5. Approve pool to spend tokens
        std::string approve_tx = from_token.approve(pool_addr, amount, private_key);
        std::cout << "Approval transaction: " << approve_tx << std::endl;

        // 6. Execute exchange
        std::string swap_tx = pool.exchange(0, 1, amount, min_output, user_address, private_key);
        std::cout << "Swap transaction: " << swap_tx << std::endl;

        return swap_tx;
    }

    // Method 2: Modern exchange_received (no approval needed)
    std::string swapWithExchangeReceived(
        const std::string& from_token_addr,
        const std::string& to_token_addr,
        uint64_t amount,
        double slippage_tolerance = 0.01) {

        std::cout << "\n=== Modern Swap with exchange_received ===" << std::endl;

        // 1. Find suitable pool
        std::string pool_addr = registry->find_pool_for_coins(from_token_addr, to_token_addr);
        if (pool_addr.empty()) {
            throw std::runtime_error("No pool found for token pair");
        }

        std::cout << "Found pool: " << pool_addr << std::endl;

        // 2. Create token and pool instances
        ERC20Token from_token(from_token_addr, rpc);
        CurvePool pool(pool_addr, rpc);

        // 3. Check balance
        uint64_t balance = from_token.balanceOf(user_address);
        if (balance < amount) {
            throw std::runtime_error("Insufficient balance");
        }

        // 4. Get expected output with slippage protection
        uint64_t expected_output = pool.get_dy(0, 1, amount);
        uint64_t min_output = static_cast<uint64_t>(expected_output * (1.0 - slippage_tolerance));

        std::cout << "Expected output: " << expected_output << std::endl;
        std::cout << "Minimum output (with slippage): " << min_output << std::endl;

        // 5. Transfer tokens directly to pool
        std::string transfer_tx = from_token.transfer(pool_addr, amount, private_key);
        std::cout << "Transfer transaction: " << transfer_tx << std::endl;

        // 6. Execute exchange_received
        std::string swap_tx =
            pool.exchange_received(0, 1, amount, min_output, user_address, private_key);
        std::cout << "Swap transaction: " << swap_tx << std::endl;

        return swap_tx;
    }

    // Method 3: Multi-hop swap using exchange_received
    std::string multiHopSwap(
        const std::vector<std::string>& token_path,
        const std::vector<std::string>& pool_path,
        uint64_t amount_in,
        double slippage_tolerance = 0.01) {

        std::cout << "\n=== Multi-hop Swap ===" << std::endl;

        if (token_path.size() != pool_path.size() + 1) {
            throw std::runtime_error("Invalid path lengths");
        }

        // For each hop in the path
        uint64_t current_amount = amount_in;
        std::string last_tx_hash;

        for (size_t i = 0; i < pool_path.size(); ++i) {
            std::cout << "\n--- Hop " << (i + 1) << " ---" << std::endl;

            ERC20Token current_token(token_path[i], rpc);
            CurvePool current_pool(pool_path[i], rpc);

            // Calculate expected output
            uint64_t expected_output = current_pool.get_dy(0, 1, current_amount);
            uint64_t min_output = static_cast<uint64_t>(expected_output * (1.0 - slippage_tolerance));

            std::cout << "Input amount: " << current_amount << std::endl;
            std::cout << "Expected output: " << expected_output << std::endl;

            if (i == 0) {
                // First hop: transfer from user to pool
                std::string transfer_tx = current_token.transfer(pool_path[i], current_amount, private_key);
                std::cout << "Transfer transaction: " << transfer_tx << std::endl;
            }

            // Determine receiver for this hop
            std::string receiver = (i == pool_path.size() - 1) ? user_address : pool_path[i + 1];

            // Execute exchange_received
            last_tx_hash =
                current_pool.exchange_received(0, 1, current_amount, min_output, receiver, private_key);
            std::cout << "Swap transaction: " << last_tx_hash << std::endl;

            current_amount = expected_output;  // Use expected output for next hop calculation
        }

        return last_tx_hash;
    }

    // Method 4: Execute limit order using the swapper infrastructure
    bool executeLimitOrderWithSwapper(const LimitOrder& order, int token_in_index, int token_out_index) {
        auto now = std::chrono::system_clock::now();

        if (order.tif == TimeInForce::GTT && now > order.expiry_time) {
            std::cout << "[Swapper] GTT order expired\n";
            return false;
        }

        try {
            // Find pool for the token pair
            std::string pool_addr = registry->find_pool_for_coins(order.input_token, order.output_token);
            if (pool_addr.empty()) {
                std::cout << "[Swapper] No pool found for token pair\n";
                return false;
            }

            CurvePool pool(pool_addr, rpc);
            
            // Get current price
            uint64_t expected_output = pool.get_dy(token_in_index, token_out_index, order.input_amount);
            double current_price = static_cast<double>(expected_output) / order.input_amount;
            double min_acceptable_price = order.limit_price * (1 - order.slippage_tolerance);

            std::cout << "[Swapper] Current price: " << current_price << ", Min acceptable price: " << min_acceptable_price << std::endl;

            bool price_met = (current_price >= min_acceptable_price);
            if (!price_met) {
                switch (order.tif) {
                    case TimeInForce::GTC:
                    case TimeInForce::GTT:
                        std::cout << "[Swapper] Price not met, retrying...\n";
                        return false;
                    case TimeInForce::IOC:
                        std::cout << "[Swapper] IOC price not met, canceling order.\n";
                        return false;
                    case TimeInForce::FOK:
                        std::cout << "[Swapper] FOK cannot fill entire order at limit price, canceling.\n";
                        return false;
                }
            }

            std::cout << "[Swapper] Price met, executing swap with exchange_received method...\n";
            
            // Execute using the modern exchange_received method
            swapWithExchangeReceived(order.input_token, order.output_token, order.input_amount, order.slippage_tolerance);
            
            return true;

        } catch (const std::exception& e) {
            std::cerr << "[Swapper] Error executing limit order: " << e.what() << std::endl;
            return false;
        }
    }
};

// === Main function ===
int main() {
    try {
        curl_global_init(CURL_GLOBAL_DEFAULT);

        // Configuration
        const std::string rpc_url = "https://sepolia.infura.io/v3/dcb2ced69e0e4cd0be14fa88c0a85596";
        const std::string wallet = "0x1C7941cC828e77E3A94405e4a4C530038C3dDF5A";
        const std::string private_key = read_private_key_from_file("private_key.txt");
        
        if (private_key.empty()) {
            std::cerr << "Private key not loaded. Exiting.\n";
            return 1;
        }

        const std::string erc20_contract = "0x0FA8781a83E46826621b3BC094Ea2A0212e71B23"; // Sepolia USDC
        const std::string curve_pool_contract = ""; // must set actual contract!

        // Initialize RPC client
        EthereumRPC rpc(rpc_url);

        // Print initial balances
        print_eth_balance(rpc_url, wallet);
        print_erc20_balance(rpc_url, wallet, erc20_contract);

        // Initialize the advanced swapper
        CurveSwapper swapper(&rpc, wallet, private_key);

        int token_in_index = 0;
        int token_out_index = 1;

        std::cout << "\n=== Merged Curve Trading System ===\n";
        std::cout << "Choose trading mode:\n";
        std::cout << "1. Traditional Limit Orders (Legacy)\n";
        std::cout << "2. Advanced Swap with Approval\n";
        std::cout << "3. Modern Swap with Exchange Received\n";
        std::cout << "4. Multi-hop Swap\n";
        std::cout << "5. Limit Order with Advanced Swapper\n";
        std::cout << "Enter choice (1-5): ";

        int mode_choice = 0;
        std::cin >> mode_choice;

        if (mode_choice == 1) {
            // Legacy limit order system
            std::cout << "Choose Time-In-Force policy:\n";
            std::cout << "1. GTC (Good-Till-Canceled)\n2. GTT (Good-Till-Time)\n3. IOC (Immediate-Or-Cancel)\n4. FOK (Fill-Or-Kill)\nEnter choice (1-4): ";

            int choice = 0;
            std::cin >> choice;

            TimeInForce tif;
            switch(choice) {
                case 1: tif = TimeInForce::GTC; break;
                case 2: tif = TimeInForce::GTT; break;
                case 3: tif = TimeInForce::IOC; break;
                case 4: tif = TimeInForce::FOK; break;
                default:
                    std::cerr << "Invalid choice, defaulting to GTC\n";
                    tif = TimeInForce::GTC;
            }

            auto now = std::chrono::system_clock::now();
            LimitOrder order = {
                "USDC",
                100 * (uint64_t)1e6,
                "DAI",
                1.001,
                0.005,
                tif,
                now + std::chrono::seconds(30)
            };

            std::cout << "===== Running legacy limit order =====\n";

            bool executed = false;
            if (order.tif == TimeInForce::GTC || order.tif == TimeInForce::GTT) {
                int retries = 0;
                const int max_retries = 5;
                while (retries < max_retries) {
                    executed = execute_limit_order(order, rpc_url, curve_pool_contract, token_in_index, token_out_index, wallet, private_key);
                    if (executed) {
                        std::cout << "Order executed successfully!\n";
                        break;
                    }
                    if (order.tif == TimeInForce::GTT && std::chrono::system_clock::now() > order.expiry_time) {
                        std::cout << "Order expired without execution\n";
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    retries++;
                }
                if (!executed && retries >= max_retries) {
                    std::cout << "Max retries reached for order\n";
                }
            } else {
                executed = execute_limit_order(order, rpc_url, curve_pool_contract, token_in_index, token_out_index, wallet, private_key);
                if (executed) {
                    std::cout << "Order executed successfully!\n";
                } else {
                    std::cout << "Order cancelled due to IOC/FOK and price not met\n";
                }
            }

        } else if (mode_choice >= 2 && mode_choice <= 4) {
            // Advanced swapper modes
            std::string USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";  // USDC
            std::string WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";  // WETH
            std::string CRV = "0xD533a949740bb3306d119CC777fa900bA034cd52";   // CRV

            uint64_t amount = 1000 * 1e6;  // 1000 USDC (6 decimals)

            try {
                if (mode_choice == 2) {
                    std::string tx = swapper.swapWithApproval(USDC, WETH, amount);
                    std::cout << "\nFinal transaction hash: " << tx << std::endl;
                } else if (mode_choice == 3) {
                    std::string tx = swapper.swapWithExchangeReceived(USDC, WETH, amount);
                    std::cout << "\nFinal transaction hash: " << tx << std::endl;
                } else if (mode_choice == 4) {
                    std::vector<std::string> token_path = {USDC, WETH, CRV};
                    std::vector<std::string> pool_path = {
                        "0x4DEcE678ceceb27446b35C672dC7d61F30bAD69E",  // USDC/WETH pool
                        "0x9D0464996170c6B9e75eED71c68B99dDEDf279e8"   // WETH/CRV pool
                    };
                    std::string tx = swapper.multiHopSwap(token_path, pool_path, amount);
                    std::cout << "\nMulti-hop final transaction hash: " << tx << std::endl;
                }
            } catch (const std::exception& e) {
                std::cerr << "Advanced swap failed: " << e.what() << std::endl;
            }

        } else if (mode_choice == 5) {
            // Limit order with advanced swapper
            std::cout << "Choose Time-In-Force policy:\n";
            std::cout << "1. GTC (Good-Till-Canceled)\n2. GTT (Good-Till-Time)\n3. IOC (Immediate-Or-Cancel)\n4. FOK (Fill-Or-Kill)\nEnter choice (1-4): ";

            int choice = 0;
            std::cin >> choice;

            TimeInForce tif;
            switch(choice) {
                case 1: tif = TimeInForce::GTC; break;
                case 2: tif = TimeInForce::GTT; break;
                case 3: tif = TimeInForce::IOC; break;
                case 4: tif = TimeInForce::FOK; break;
                default:
                    std::cerr << "Invalid choice, defaulting to GTC\n";
                    tif = TimeInForce::GTC;
            }

            auto now = std::chrono::system_clock::now();
            LimitOrder order = {
                erc20_contract,  // Input token (USDC)
                100 * (uint64_t)1e6,  // 100 USDC
                "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  // Output token (mainnet USDC for example)
                1.001,
                0.005,
                tif,
                now + std::chrono::seconds(30)
            };

            std::cout << "===== Running advanced limit order =====\n";

            bool executed = false;
            if (order.tif == TimeInForce::GTC || order.tif == TimeInForce::GTT) {
                int retries = 0;
                const int max_retries = 5;
                while (retries < max_retries) {
                    executed = swapper.executeLimitOrderWithSwapper(order, token_in_index, token_out_index);
                    if (executed) {
                        std::cout << "Advanced limit order executed successfully!\n";
                        break;
                    }
                    if (order.tif == TimeInForce::GTT && std::chrono::system_clock::now() > order.expiry_time) {
                        std::cout << "Order expired without execution\n";
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    retries++;
                }
                if (!executed && retries >= max_retries) {
                    std::cout << "Max retries reached for advanced order\n";
                }
            } else {
                executed = swapper.executeLimitOrderWithSwapper(order, token_in_index, token_out_index);
                if (executed) {
                    std::cout << "Advanced limit order executed successfully!\n";
                } else {
                    std::cout << "Advanced order cancelled due to IOC/FOK and price not met\n";
                }
            }
        }

        curl_global_cleanup();

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        curl_global_cleanup();
        return 1;
    }

    return 0;
}