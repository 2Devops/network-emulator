#pragma once

namespace netapi {

struct FailState {
    int failProbability;
    bool haveFailed;
    bool continueFailing;
    bool failUnfailable;

};

}
