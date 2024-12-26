# ZK Solvency Demo

一个使用零知识证明技术实现的交易所偿付能力证明系统。

## 功能特性

- 支持大规模用户数据的高效处理
- 使用Merkle树优化存储和证明
- 实现了完整的零知识证明流程
- 基于Groth16证明系统

## 使用说明

### 1. 生成密钥

```bash
# 生成支持100个用户的密钥对
go run main.go keygen -batch 100 -out ./keys
```

### 2. 生成证明

```bash
# 准备输入数据 (参考 test/data/users.json)
# 生成证明
go run main.go prove -input ./test/data/users.json -keys ./keys -output proof.json
```

### 3. 验证证明

```bash
# 验证生成的证明
go run main.go verify -proof proof.json -key ./keys/verifying_100.key
```

## 项目结构

```
zk-solvency-demo/
├── cmd/          # 命令行工具
├── internal/     # 内部实现
├── pkg/          # 公共包
└── test/         # 测试文件
```

## 开发指南

### 运行测试

```bash
go test ./...
```

### 生成文档

```bash
godoc -http=:6060
```

## 示例数据

在 `test/data/` 目录下提供了示例数据:
- `users.json`: 用户资产数据示例
- `exchange.json`: 交易所资产数据示例

## 贡献指南

1. Fork 项目
2. 创建特性分支
3. 提交更改
4. 推送到分支
5. 创建 Pull Request

## 许可证

MIT License