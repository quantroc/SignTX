pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/Strings.sol";

contract VerifySig {
    function verify(address _signer, string memory _message, bytes memory _sig)
        external pure returns (bool)
    {
        bytes32 messageHash = getMessageHash(_message);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);
        
        return recover(ethSignedMessageHash, _sig) == _signer;
    }

    function getMessageHash(string memory _message) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_message));
    }
    function getEthSignedMessageHash(bytes32 _messageHash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32",_messageHash));
    }

    function recover(bytes32 _etheSignedMessageHash, bytes memory _sig)
        public pure returns(address)
    {
        (bytes32 r, bytes32 s, uint8 v) = _split(_sig);
        return ecrecover(_etheSignedMessageHash, v, r, s);
    }

    function _split(bytes memory _sig) internal pure
        returns (bytes32 r, bytes32 s, uint8 v)
    {
        require(_sig.length == 65,"invalid signature length");

        assembly {
            r :=mload(add(_sig,32))
            s :=mload(add(_sig, 64))
            v :=byte(0, mload(add(_sig, 96)))
        }
    }
    struct ExchangeData {
        bool is721;
        address token;
        uint256 tokenId;
        uint256 prevTotal;
        uint256 value;
        address priceToken;
        uint256 price;
        address payable owner;
        string salt;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }
///////////// Verification Functions /////////////
    function _generateKey(address token, uint256 tokenId, uint256 value, address priceToken, uint256 price, string memory salt) internal pure returns (bytes32 key) {
        key = keccak256(abi.encode(token, tokenId, value, priceToken, price, salt));
    }

    function generateKey(address token, uint256 tokenId, uint256 value, address priceToken, uint256 price, string memory salt) external pure returns (bytes32 key) {
        key = _generateKey(token, tokenId, value, priceToken, price, salt);
    }

    function generateMessage(address token, uint256 tokenId, uint256 value, address priceToken, uint256 price, string memory salt) external pure returns (string memory _message) {
        _message = _generateKey(token, tokenId, value, priceToken, price, salt).toString();
    }

    function verifyOrder(ExchangeData memory data) public pure returns (bool verified) {
        bytes32 _message = _generateKey(data.token, data.tokenId, data.prevTotal, data.priceToken, data.price, data.salt);
        address confirmed = _message.toString().recover(data.v, data.r, data.s);
        return (confirmed == data.owner);
    }
}
