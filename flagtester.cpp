#include "flagtester.h"

namespace netapi {

FlagTester::FlagTester(const std::vector<int> _validFlags) :
    validFlags(_validFlags) {
    validFlagsUint = 0;

    for ( const auto& F : validFlags ) {
        if ( F < 0 ) {
            throw std::runtime_error("FlagTester: negative valid flags not allowed");
        }

        if ( std::bitset<31>((uint32_t)F).count() != 1 ) {
            throw std::runtime_error("FlagTester: only single-bit valid flags allowed");
        }

        validFlagsUint |= F;
    }
}

bool FlagTester::IsValid(const int flags) const {
    if ( flags == 0 ) {
        return true;
    }

    if ( flags < 0 ) {
        return false;
    }

    const unsigned int flagsUint = (unsigned int)flags;
    const unsigned int validFlagsInv = ~validFlagsUint;

    /* TODO untested */
    if ( (~flagsUint & validFlagsInv) == 0 ) {
        return false;
    }

    return true;
}

} /* namespace netapi */
