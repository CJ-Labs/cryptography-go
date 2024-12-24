前置知识
1.  标量 (Scalar)
  - 标量就是一个普通的数字
  - 可以进行普通的数学运算
  - 在 EdDSA 中通常是模 L 的值（L 是曲线阶数）
2. 点（point）
  - 点是曲线上的一个坐标，由 (x,y) 组成
  - 不能直接进行普通的数学运算
3. 标量乘法
  - 标量 * 点 = 新的点
  - 3 * B = B + B + B = (x₅, y₅)
  -  公钥 = 私钥 * B
4. 点加法
  - P₁ = (x₁, y₁)
  - P₂ = (x₂, y₂)
  - P₁ + P₂ = (x₃, y₃)

---
1. 曲线参数
曲线方程：-x² + y² = 1 - dx²y²
- d：Edwards 曲线参数
- B：基点（生成点）
- L：曲线阶数（子群阶数）
2. 密钥生成
- 私钥： 随机生成的 32字节数据
输入：32字节私钥
输出：64字节哈希值
|--------------------------------|--------------------------------|
        前32字节 (a)                      后32字节 (prefix)
用于生成公钥（需要特殊处理）                用于后续生成签名
- 处理私钥
  - H = SHA-512(种子)    // 64字节输出
  - 前32字节： 用于生成公钥的标量 a
  - 后32字节：prefix，保存用于生成签名
- 生成公钥
  - A = a * B    // a是处理后的前32字节
3. 签名过程
1. 计算 r 值
  - r = SHA-512(prefix || 消息) // prefix是私钥哈希的后32字节
2. 计算点 R
  -  R = r * B   // r 为标量
3. 计算 h 值
  - h = SHA-512(R || A || 消息)    // A是公钥
4. 计算 s
  s = r + h * a
  - a 是处理后的私钥标量（前32字节）
  - L 是曲线阶数
5. 返回签名 = (R, s)
  - R 是压缩的点 （32字节）
  - s 是标量（32字节）
4. 验证推导过程
4.1 已知数据
  - 签名: (R, s)    // 32字节 + 32字节
  - 公钥: A         // 32字节
  - 消息: M
  - 基点: B
4.2 验证等式推导
  - 从签名方程开始
  s = r + h * a  // a 是处理后的私钥标量
  - 两边✖️ 基点 B
  s * B = (r + h * a) * B
  - 右边展开
  s * B = r * B + h * a * B
  代入已知条件
  - r * B = R        // 签名中的 R 点
  - a * B = A  // 公钥
  最终得到
  s * B = R + h * A
4.3 具体验证步骤
1. 计算 h
   h = SHA-512(R || 公钥 || 消息)
2. 计算左边
s * B 基点 B ✖️ s
3. 计算右边
  - 先计算 h * 公钥 （标量乘法）
  - 加上点 R （点加法）
4. 验证
- Left == right 签名有效


---
验证者拥有：
- 公钥 A
- 签名 (R, s)
- 消息 M

可以计算：
- h = SHA-512(R || A || M)
- 检查 s * B ?= R + h * A


---
Alice 和 Bob 举例
1. Alice 的密钥生成
  1. Alice 生成密钥
  alice_key = 随机32字节
  = 1234...5678 (32字节)
  2. 处理私钥
  H = SHA-512(alice_key) 64字节
    1. 分成两部分
    alice_key = H[0:32]  前32字节，用于生成公钥
    alice_prefix = H[32:64]后32字节， 用于签名
  3. 生成公钥
  alice_public = alice_key * B = A点(x, y) 
2. Alice 签名消息
Alice 要给 Bob 发送消息 "Hello Bob!"
  1. 计算 r
  r = SHA-512(alice_prefix || "Hello Bob!")
  2. 计算点 R
  R = r * B  R 是曲线上的点
  3. 计算 h
  h = SHA-512(R || alice_public || "Hello Bob!")
  4. 计算 s
  s = r + h * alice_key
  5. 生成签名
  signature = (R, s) R是点，s是数字
发送给Bob
  - 消息: "Hello Bob!" （M）
  - 签名: (R, s)
  - 公钥: alice_public （公钥A）
3. Bob 验证签名
Bob 收到
  - 消息: "Hello Bob!" （M）
  - 签名: (R, s)
  - 公钥: alice_public （公钥A）
1. 计算 h
h = SHA-512(R || alice_public || "Hello Bob!")
2. 验证等式
- Left =  s * B
- Right = R + h * A
3. Left == right 验证签名正确

---
4.  Bob 可以确信这是 Alice 的签名
1. 只有 Alice 知道私钥(alice_key)，所以只有她能计算出正确的 s
 s = r + h * alice_key

2. Bob 通过验证等式确认：
 s * B = R + h * A