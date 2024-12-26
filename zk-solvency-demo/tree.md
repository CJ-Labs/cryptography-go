zk-solvency-demo/
├── README.md                 # 项目说明文档
├── go.mod                    # Go模块定义
├── go.sum                    # 依赖版本锁定
│
├── cmd/                      # 命令行入口
│   ├── keygen/              # 密钥生成工具
│   │   └── main.go
│   ├── prover/              # 证明生成工具
│   │   └── main.go
│   └── verifier/            # 证明验证工具
│       └── main.go
│
├── internal/                 # 内部包
│   ├── circuit/             # 电路实现
│   │   ├── circuit.go       # 电路定义
│   │   └── circuit_test.go  # 电路测试
│   │
│   ├── r1cs/                # R1CS约束系统
│   │   ├── generator.go     # R1CS生成器
│   │   └── generator_test.go
│   │
│   ├── witness/             # Witness生成
│   │   ├── generator.go     # Witness生成器
│   │   └── generator_test.go
│   │
│   └── merkle/              # Merkle树实现
│       ├── tree.go
│       └── tree_test.go
│
├── pkg/                      # 公共包
│   ├── types/               # 数据类型定义
│   │   └── types.go
│   │
│   └── utils/               # 工具函数
│       ├── utils.go
│       └── utils_test.go
│
└── test/                    # 集成测试
    ├── data/                # 测试数据
    │   ├── users.json
    │   └── exchange.json
    │
    └── integration_test.go