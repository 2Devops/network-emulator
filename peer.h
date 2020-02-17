#pragma once

#include "datasource.h"

#include <stdint.h>
#include <vector>

namespace netapi {

class Address {
    public:
        typedef enum {
            ADDRESS_TYPE_IPV4 = 1,
            ADDRESS_TYPE_IPV6 = 2,
        } address_type_t;
        Address(const address_type_t _addressType, const std::vector<uint8_t>& _address);
        int GetAddressFamily(void) const;
        virtual ~Address(void) { }
        std::vector<uint8_t> GetBytes(void) const;
        Address operator&(const Address& in) const;
        Address operator|(const Address& in) const;
    private:
        const address_type_t addressType;
        std::vector<uint8_t> address;
        void assertSameType(const Address& in) const;
};

class AddressIPV4 : public Address {
    public:
        AddressIPV4(const std::vector<uint8_t>& _address);
};

class AddressIPV6 : public Address {
    public:
        AddressIPV6(const std::vector<uint8_t>& _address);
};

class AddressConstraint {
    public:
        AddressConstraint(void);
        virtual ~AddressConstraint(void) { }
        virtual bool ValidateAddress(const Address& address) const = 0;
        virtual Address MakeAddressValid(const Address& address) const = 0;
};

class AddressNetmaskConstraint : public AddressConstraint {
    private:
        std::vector<uint8_t> netmaskIPV4;
        std::vector<uint8_t> netmaskIPV6;
    public:
        AddressNetmaskConstraint(const std::vector<uint8_t>& _netmaskIPV4, const std::vector<uint8_t>& _netmaskIPV6);
        bool ValidateAddress(const Address& address) const override;
        Address MakeAddressValid(const Address& address) const override;
};

class AddressCallbackConstraint : public AddressConstraint {
    public:
        typedef bool (*validateaddress_callback)(const Address& address);
        typedef Address (*makeaddressvalid_callback)(const Address& address);
        AddressCallbackConstraint(
                const validateaddress_callback _validateAddressCallback,
                const makeaddressvalid_callback _makeAddressValidCallback
                );
        bool ValidateAddress(const Address& address) const override;
        Address MakeAddressValid(const Address& address) const override;
    private:
        validateaddress_callback validateAddressCallback;
        makeaddressvalid_callback makeAddressValidCallback;
};

class Peer {
    public:
        Peer(const std::vector<AddressConstraint> _constraints = std::vector<AddressConstraint>());
        virtual ~Peer(void) { }
        virtual Address GenerateAddress(const Address::address_type_t _type) = 0;
    private:
        std::vector<AddressConstraint> addressConstraints;
    protected:
        bool ValidateAddress(const Address& address) const;
};

class PeerCallback : public Peer {
    public:
        typedef Address (*generateaddress_cb_t)(const Address::address_type_t _type);
        PeerCallback(const generateaddress_cb_t _generateAddressCallback);
        Address GenerateAddress(const Address::address_type_t _type) override;
    private:
        const generateaddress_cb_t generateAddressCallback;
};

class PeerDataSource : public Peer {
    private:
        DataSource& ds;
    public:
        PeerDataSource(DataSource& ds);
        Address GenerateAddress(const Address::address_type_t _type) override;
};

} /* namespace netapi */
