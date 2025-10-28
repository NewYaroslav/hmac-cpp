#include <iostream>

extern "C" bool secure_zero_memset_s_branch();
extern "C" bool secure_zero_explicit_bzero_branch();

int main() {
    const bool memset_ok = secure_zero_memset_s_branch();
    const bool explicit_ok = secure_zero_explicit_bzero_branch();

    if (!memset_ok || !explicit_ok) {
        std::cout << "secure_zero failed: memset_s=" << memset_ok
                  << ", explicit_bzero=" << explicit_ok << "\n";
        return 1;
	}
	
	std::cout << "secure_zero zeroed buffers across translation units\n";
    return 0;
}