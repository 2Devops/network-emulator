#pragma once

#include <map>
#include <stddef.h>
#include "posix_include.h"

namespace netapi {

class NetAPI {
    public:
        NetAPI(void) { }
        virtual ~NetAPI(void) { };

#include "netapi_method_decl.h"
};


} /* namespace netapi */
