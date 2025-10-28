#include <iostream>

extern "C" int secure_zero_branch_memsets();
extern "C" int secure_zero_branch_manual();

int main() {
    const auto a = secure_zero_branch_memsets();
    const auto b = secure_zero_branch_manual();
    if (a == b) {
        std::cout << "secure_zero branch matches across TUs: " << a << "\n";
        return 0;
    }

    std::cout << "secure_zero branch mismatch across TUs: " << a << " vs " << b << "\n";
    return 1;
}