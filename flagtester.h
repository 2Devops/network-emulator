#pragma once

#include <vector>
#include <stdexcept>
#include <bitset>

namespace netapi {

class FlagTester {
    private:
        const std::vector<int> validFlags;
        unsigned int validFlagsUint;
    public:
        FlagTester(const std::vector<int> _validFlags);
        bool IsValid(const int flags) const;
};


} /* namespace netapi */
