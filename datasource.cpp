#include "datasource.h"

#include <stdexcept>
#include <cstring>

namespace netapi {

std::vector<uint8_t> DataSourceSingle::GetDataVec(const datasource_id id, const size_t max) {
    std::vector<uint8_t> ret;
    ret.resize(max);
    const auto realSize = GetData(id, ret.data(), max);

    /* TODO assert realSize <= max */
    ret.resize(realSize);

    return ret;
}

size_t DataSourceSingle::GetData(const datasource_id id, void* dest, const size_t max) {
    const int get_num = GetInt(id, 0 , max);

    /* Shouldn't happen */
    if ( get_num < 0 ) {
        throw std::runtime_error("GetData: unexpected condition");
    }

    if ( get_num == 0 ) {
        return 0;
    }

    if ( GetDataExact(id, dest, (size_t)get_num) == 0 ) {
        memset(dest, 0, get_num);
    }

    return get_num;
}

size_t DataSourceSingle::GetDataExact(const datasource_id id, void* dest, const size_t size) {
    (void)id; /* id is unused in DataSourceSingle */
    if ( left < size ) {
        return 0;
    }

    memcpy(dest, data, size);
    data += size;
    left -= size;

    return size;
}

int DataSourceSingle::GetInt(const datasource_id id, const int min, const int max) {
    if ( min > max ) {
        throw std::runtime_error("GetInt: min > max");
    }

    if ( min < 0 || max < 0 ) {
        throw std::runtime_error("GetInt: negative values unsupported");
    }

    if ( min == max ) return min;

    const int delta = max - min;

    unsigned int val;

    if ( GetDataExact(id, &val, sizeof(val)) != sizeof(val) ) {
        return min;
    }

    val %= (delta+1);
    val += min;

    return (int)val;
}

size_t DataSourceSingle::Choice(const datasource_id id, const std::vector<size_t> choices) {
    switch ( choices.size() ) {
        case    0:
            throw std::runtime_error("DataSource: attempted Choice() on zero choices");
            break;
        case    1:
            return choices[0];
        default:
            const size_t choice = GetInt(id, 0, choices.size() - 1);
            return choices[choice];
    }
}

} /* namespace netapi */
