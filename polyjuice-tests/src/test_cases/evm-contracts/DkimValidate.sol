pragma solidity >=0.8.0;

contract DkimValidate {
    event DkimValidateEvent(bytes32, bytes32, bytes32, bytes32, bytes, bytes);

    function validate(
        uint32 e,
        bytes memory n,
        bytes memory selector,
        bytes memory _sdid,
        bytes memory email
    ) public {
        bytes memory input = abi.encodePacked(uint32(email.length), email);
        bytes memory output;
        assembly {
            let len := mload(input)
            let ret := call(not(0), 0xf5, 0x0, add(input, 0x20), len, 0, 0)
            if iszero(ret) {
                revert(ret, 4)
            }
            output := mload(0x40)
            mstore(
                0x40,
                add(
                    output,
                    and(add(add(returndatasize(), 0x20), 0x1f), not(0x1f))
                )
            )
            mstore(output, returndatasize())
            returndatacopy(add(output, 0x20), 0, returndatasize())
        }
        (
            bytes32 from_hash,
            bytes32 subject_hash,
            bytes32 dkim_selector,
            bytes32 sdid,
            bytes memory dkim_sig,
            bytes memory dkim_msg
        ) = abi.decode(
                output,
                (bytes32, bytes32, bytes32, bytes32, bytes, bytes)
            );
        emit DkimValidateEvent(
            from_hash,
            subject_hash,
            dkim_selector,
            sdid,
            dkim_sig,
            dkim_msg
        );
    }
}
