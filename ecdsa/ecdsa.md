# ECDSA 签名与验证

## 1. 基础参数

### 曲线参数
- **p**: 定义曲线的素数，表示曲线在有限域上的定义（secp256k1）
- **a** 和 **b**: 椭圆曲线方程 $$𝑦^2=𝑥^3+𝑎𝑥+𝑏$$ 中的参数
  - secp256k1: a = 0, b = 7

### 关键点
- **生成点 (G)**: 
  - Gx 和 Gy: 定义椭圆曲线上的生成点 G 的坐标
  - 用于密钥生成和签名过程的基础点
- **曲线阶数 (n)**: 
  - 生成点 G 的阶数
  - 表示通过 G 生成的所有点的数量

## 2. 签名过程

### 2.1 签名方程
- r = x
- r = x_R mod n (R = k G 的 x 坐标)
- s = k⁻¹ (hash + r privateKey)


### 2.2 签名步骤
1. 生成随机数 k
2. 计算点 R = k * G
3. 取 R 的 x 坐标作为 r
4. 计算 s = k⁻¹ * (hash + r * privateKey)

## 3. 验证过程

### 3.1 数学推导
- s = k⁻¹(hash + r私钥)
- sk = hash + r私钥
- k = hash/s + r私钥/s
- k = u1 + u2私钥 (其中 w = 1/s)

### 3.2 计算 u1 和 u2
w = 1/s
u1 = hash * w
u2 = r * w


### 3.3 验证步骤
1. 计算点 point1 = u1 * G
2. 计算点 point2 = u2 * 公钥
3. 计算 R' = point1 + point2
4. 验证 R' 的 x 坐标是否等于 r

## 4. Recovery ID (v值)

### 4.1 基本概念
- recovery_id 就是 RSV 中的 v
- 用于标识使用哪个点来恢复公钥
- 取值范围：0 或 1

### 4.2 为什么需要 recovery_id
- 椭圆曲线上每个 y 坐标对应两个可能的点
- 用于指示使用曲线上的哪个点来恢复公钥

### 4.3 v值的不同格式
1. **原始格式**: v = recovery_id (0 或 1)
2. **传统以太坊格式**: v = recovery_id + 27 (27 或 28)
3. **EIP-155格式**: v = chainID * 2 + 35 + recovery_id

## 5. 实际应用示例

### 5.1 Alice 签名过程
- 私钥 = 123 (私密)
- 公钥 = 123 G (公开)
- K = 随机数
- R = k G // R 点的 x 坐标就是 r
- s = k⁻¹ (hash + r privateKey)


### 5.2 Bob 验证过程

- point1 = u1 G
- point2 = u2 公钥 // 使用 alice 的公钥
- R' = point1 + point2
- 验证 R' 的 x 坐标 == r
