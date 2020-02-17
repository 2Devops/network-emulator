#include "peer.h"
#include <stdexcept>
#include <string.h>
#include <sys/socket.h>

namespace netapi {

/* class Address */

Address::Address(const address_type_t _addressType, const std::vector<uint8_t>& _address) :
    addressType(_addressType), address(_address) {
}

int Address::GetAddressFamily(void) const {
    switch ( addressType ) {
        case    ADDRESS_TYPE_IPV4:
            return AF_INET;
        case    ADDRESS_TYPE_IPV6:
            return AF_INET6;
        default:
            throw std::runtime_error("Invalid address type");
    }
}

std::vector<uint8_t> Address::GetBytes(void) const {
    return address;
}

Address Address::operator&(const Address& in) const {
    assertSameType(in);

    /* copy */
    Address ret = in;

    for (size_t i = 0; i < address.size(); i++) {
        ret.address[i] &= address[i];
    }

    return ret;
}

Address Address::operator|(const Address& in) const {
    assertSameType(in);

    /* copy */
    Address ret = in;

    for (size_t i = 0; i < address.size(); i++) {
        ret.address[i] |= address[i];
    }

    return ret;
}

void Address::assertSameType(const Address& in) const {
    if ( in.GetAddressFamily() != GetAddressFamily() || in.address.size() != address.size() ) {
        throw std::runtime_error("Mismatching address families");
    }
}

/* class AddressIPV4 */

AddressIPV4::AddressIPV4(const std::vector<uint8_t>& _address) :
    Address(ADDRESS_TYPE_IPV4, _address) {

    if ( _address.size() != 4 ) {
        throw std::runtime_error("AddressIPV4 constructor: input address not 4 bytes");
    }
}

/* class AddressIPV6 */

AddressIPV6::AddressIPV6(const std::vector<uint8_t>& _address) :
    Address(ADDRESS_TYPE_IPV6, _address) {

    if ( _address.size() != 16 ) {
        throw std::runtime_error("AddressIPV6 constructor: input address not 16 bytes");
    }
}

/* class AddressConstraint */

AddressConstraint::AddressConstraint(void) {
}

/* class AddressNetmaskConstraint */

AddressNetmaskConstraint::AddressNetmaskConstraint(const std::vector<uint8_t>& _netmaskIPV4, const std::vector<uint8_t>& _netmaskIPV6) :
    AddressConstraint(), netmaskIPV4(_netmaskIPV4), netmaskIPV6(_netmaskIPV6) {
        const static uint8_t netmaskIPV4Null[4] = { 0 };
        const static uint8_t netmaskIPV6Null[4] = { 0 };

        if ( netmaskIPV4.size() != 4 || memcmp(netmaskIPV4.data(), netmaskIPV4Null, 4) == 0 ) {
            throw std::runtime_error("Invalid IPv4 netmask");
        }

        if ( netmaskIPV6.size() != 16 || memcmp(netmaskIPV6.data(), netmaskIPV6Null, 16) == 0 ) {
            throw std::runtime_error("Invalid IPv6 netmask");
        }

        /* invert */

        for (size_t i = 0; i < netmaskIPV4.size(); i++) {
            netmaskIPV4[i] = ~netmaskIPV4[i];
        }

        for (size_t i = 0; i < netmaskIPV6.size(); i++) {
            netmaskIPV6[i] = ~netmaskIPV6[i];
        }
}

bool AddressNetmaskConstraint::ValidateAddress(const Address& address) const {
    const size_t addressSize = address.GetAddressFamily() == AF_INET ? 4 : 16;

    for (size_t i = 0; i < addressSize; i++) {
    }
    /* TODO */
    return true;
}

Address AddressNetmaskConstraint::MakeAddressValid(const Address& address) const {
    switch ( address.GetAddressFamily() ) {
        case    AF_INET:
            {
                /* TODO */
                return AddressIPV4(std::vector<uint8_t>(4));
            }
            break;
        case    AF_INET6:
            {
                /* TODO */
                return AddressIPV6(std::vector<uint8_t>(16));
            }
            break;
    }

    /* unreachable */
    abort();
}

/* class AddressCallbackConstraint */

AddressCallbackConstraint::AddressCallbackConstraint(
        const validateaddress_callback _validateAddressCallback,
        const makeaddressvalid_callback _makeAddressValidCallback) :
    AddressConstraint(),
    validateAddressCallback(_validateAddressCallback),
    makeAddressValidCallback(_makeAddressValidCallback) {
}

bool AddressCallbackConstraint::ValidateAddress(const Address& address) const {
    return validateAddressCallback(address);
}

Address AddressCallbackConstraint::MakeAddressValid(const Address& address) const {
    return makeAddressValidCallback(address);
}

/* class Peer */

Peer::Peer(const std::vector<AddressConstraint> _constraints) {
    (void)_constraints; /* TODO use variable */
}

bool Peer::ValidateAddress(const Address& address) const {
    for (const auto& constraint : addressConstraints ) {
        if ( constraint.ValidateAddress(address) == false ) {
            return false;
        }
    }

    return true;
}

/* class PeerCallback */

PeerCallback::PeerCallback(const generateaddress_cb_t _generateAddressCallback) :
    Peer(), generateAddressCallback(_generateAddressCallback) {
}

Address PeerCallback::GenerateAddress(const Address::address_type_t _type) {
    return generateAddressCallback(_type);
}

/* class PeerDataSource */

PeerDataSource::PeerDataSource(DataSource& _ds) :
    Peer(), ds(_ds) {
}

Address PeerDataSource::GenerateAddress(const Address::address_type_t _type) {

    if ( _type & Address::ADDRESS_TYPE_IPV4 ) {
        std::vector<uint8_t> addr(4);
        ds.GetDataExact(-1 /* TODO ? */, addr.data(), addr.size());
        return AddressIPV4(addr);
    } else if ( _type & Address::ADDRESS_TYPE_IPV6 ) {
        std::vector<uint8_t> addr(16);
        ds.GetDataExact(-1 /* TODO ? */, addr.data(), addr.size());
        return AddressIPV6(addr);
    } else {
        throw std::runtime_error("Invalid address type specified");
    }
}

} /* namespace netapi */
