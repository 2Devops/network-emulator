#include <errno.h>
#include "artificialfailure.h"

namespace netapi {

ArtificialFailure::ArtificialFailure(
        DataSource& _ds,
        FailState& _failState,
        const datasource_id _dsid,
        const datasource_id _choice_dsid,
        const std::vector<size_t> _errnoChoices) :
    ds(_ds), failState(_failState), dsid(_dsid),
    choice_dsid(_choice_dsid), errnoChoices(_errnoChoices) {
}

size_t ArtificialFailure::getErrno(void) {
    if ( errnoChoices.size() == 0 ) {
        return 0;
    } else {
        return ds.Choice(choice_dsid, errnoChoices);
    }
}

bool ArtificialFailure::GetFailure(void) {
    //return false; /* XXX */
    if ( errnoChoices.size() == 0 && failState.failUnfailable == false ) {
        return false;
    }

    if ( failState.failProbability <= 0 ) {
        return false;
    }

    if ( failState.haveFailed == true && failState.continueFailing == true ) {
        errno = getErrno();
        return true;
    }

    int n = ds.GetInt(dsid, 0, failState.failProbability);

    if ( n == 0 ) {
        failState.haveFailed = true;
        errno = getErrno();
        return true;
    } else {
        return false;
    }
}

} /* namespace netapi */
