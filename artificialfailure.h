#pragma once

#include "datasource.h"
#include "failstate.h"
#include <vector>
#include <stddef.h>

namespace netapi {

class ArtificialFailure {
    private:
        DataSource& ds;
        FailState& failState;
        const datasource_id dsid, choice_dsid;
        const std::vector<size_t> errnoChoices;
        size_t getErrno(void);
    public:
        ArtificialFailure(
                DataSource& _ds,
                FailState& _failState,
                const datasource_id _dsid,
                const datasource_id _choice_dsid,
                const std::vector<size_t> _errnoChoices);
        bool GetFailure(void);
};

} /* namespace netapi */
