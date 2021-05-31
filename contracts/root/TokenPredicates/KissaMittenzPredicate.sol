pragma solidity 0.6.6;

import {SafeMath} from "@openzeppelin/contracts/math/SafeMath.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/SafeERC20.sol";
import {AccessControlMixin} from "../../common/AccessControlMixin.sol";
import {RLPReader} from "../../lib/RLPReader.sol";
import {ITokenPredicate} from "./ITokenPredicate.sol";
import {Initializable} from "../../common/Initializable.sol";

contract KissaMittenzPredicate is ITokenPredicate, AccessControlMixin, Initializable {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;
    using SafeERC20 for IERC20;
    using SafeMath for uint256;

    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    bytes32 public constant TOKEN_TYPE = keccak256("ERC20");
    bytes32 public constant TRANSFER_EVENT_SIG = 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef;

    // Pegged exchange rate from MITTN to KISSA.
    uint256 private constant _MittenzToKissaExRate = 400;

    // PoS Bridging can start on 10 Oct 2021 at 00:00 UTC
    // (seconds since Unix epoch)
    // REAL
    // uint constant private _convertibilityStartTimeSecs = 1633046400;
    
    // TEST/DEBUG on Mumbai
    // For testing, set start time to 2 Jun 2021 at 00:00 UTC
    uint constant private _testConvertibilityStartTimeSecs = 1622592000;

    event LockedERC20(
        address indexed depositor,
        address indexed depositReceiver,
        address indexed rootToken,
        uint256 amount
    );

    constructor() public {}

    function initialize(address _owner) external initializer {
        _setupContractId("KissaMittenzPredicate");
        _setupRole(DEFAULT_ADMIN_ROLE, _owner);
        _setupRole(MANAGER_ROLE, _owner);
    }

    /**
     * @notice Lock MITTN tokens for deposit, callable only by manager
     * @param depositor Address who wants to deposit tokens
     * @param depositReceiver Address (address) who wants to receive tokens on child chain
     * @param rootToken Token which gets deposited
     * @param depositData ABI encoded amount
     */
    function lockTokens(
        address depositor,
        address depositReceiver,
        address rootToken,
        bytes calldata depositData
    )
        external
        override
        only(MANAGER_ROLE)
    {
        // Check it is already past the earliest date and time at which conversion is allowed.
        // TEST/DEBUG on Mumbai
        require(block.timestamp > _testConvertibilityStartTimeSecs, "KISSA to MITTN conversion allowed starting 2 JUNE 2021 at 00:00 UTC.");
        // REAL
        // require(block.timestamp > _convertibilityStartTimeSecs, "KISSA to MITTN conversion allowed starting 1 OCT 2021 at 00:00 UTC.");

        uint256 amount = abi.decode(depositData, (uint256));
        // Check for the MITTN transaction limit before the LockedERC20 event is emitted.
        require(amount <= 40000 * 10**18,
            "MITTN to KISSA conversion: Conversion of more than 40,000 MITTN in a single transaction cannot proceed due to 40,000 MITTN transaction limit.");

        emit LockedERC20(depositor, depositReceiver, rootToken, amount);
        IERC20(rootToken).safeTransferFrom(depositor, address(this), amount);
    }

    /**
     * @notice Validates log signature, from and to address
     * then sends the correct amount to withdrawer
     * at pegged exchange rate between MITTN and KISSA,
     * callable only by manager
     * @param rootToken Token which gets withdrawn
     * @param log Valid ERC20 burn log from child chain
     */
    function exitTokens(
        address,
        address rootToken,
        bytes memory log
    )
        public
        override
        only(MANAGER_ROLE)
    {
        RLPReader.RLPItem[] memory logRLPList = log.toRlpItem().toList();
        RLPReader.RLPItem[] memory logTopicRLPList = logRLPList[1].toList(); // topics

        require(
            bytes32(logTopicRLPList[0].toUint()) == TRANSFER_EVENT_SIG, // topic0 is event sig
            "ERC20Predicate: INVALID_SIGNATURE"
        );

        address withdrawer = address(logTopicRLPList[1].toUint()); // topic1 is from address

        require(
            address(logTopicRLPList[2].toUint()) == address(0), // topic2 is to address
            "ERC20Predicate: INVALID_RECEIVER"
        );

        uint256 amountInKissa = logRLPList[2].toUint(); // log data field
        uint256 amountInMittenz = amountInKissa * _MittenzToKissaExRate;
        IERC20(rootToken).safeTransfer(
            withdrawer,
            amountInMittenz
        );
    }
}