pragma solidity 0.6.6;

import {UpgradableProxy} from "../../common/Proxy/UpgradableProxy.sol";

contract CustomERC1155PredicateProxy is UpgradableProxy {
    constructor(address _proxyTo)
        public
        UpgradableProxy(_proxyTo)
    {}
}
