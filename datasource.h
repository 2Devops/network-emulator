#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>

namespace netapi {

typedef const size_t datasource_id;

class DataSource {
    public:
        DataSource(void) { }
        virtual ~DataSource(void) { }

        virtual std::vector<uint8_t> GetDataVec(const datasource_id id, const size_t max) = 0;
        virtual size_t GetData(const datasource_id id, void* dest, const size_t max) = 0;
        virtual size_t GetDataExact(const datasource_id id, void* dest, const size_t size) = 0;
        virtual int GetInt(const datasource_id id, const int min, const int max) = 0;
        virtual size_t Choice(const datasource_id id, const std::vector<size_t> choices) = 0;
};

class DataSourceSingle : public DataSource {
    private:
        const uint8_t* data = nullptr;
        size_t left = 0;
    public:
        DataSourceSingle(const uint8_t* _data, const size_t _size) :
            DataSource(), data(_data), left(_size)
        { }

        std::vector<uint8_t> GetDataVec(const datasource_id id, const size_t max) override;
        size_t GetData(const datasource_id id, void* dest, const size_t max) override;
        size_t GetDataExact(const datasource_id id, void* dest, const size_t size) override;
        int GetInt(const datasource_id id, const int min, const int max) override;
        size_t Choice(const datasource_id id, const std::vector<size_t> choices) override;
};

/* VrankenFuzz */
/*
class DataSourceVF : public DataSource {
    public:
};
*/


} /* namespace netapi */
